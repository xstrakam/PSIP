using System.Security.Cryptography;
using System.Windows;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using SHA256 = System.Security.Cryptography.SHA256;

namespace psip
{
    public class MacEntry
    {
        public string MacAddress { get; init; }
        public int PortNumber { get; set; }
        public int AgingTime { get; set; }
    }
    
    public partial class MainWindow : Window
    {
        private LibPcapLiveDevice _port1, _port2;

        private readonly HashSet<string> _recentSent = new();
        private readonly Queue<string> _recentOrder = new();
        private readonly Lock _recentLock = new();
        private const int MaxRecent = 1000;
        
        private readonly Dictionary<string, long> _statsP1In = new();
        private readonly Dictionary<string, long> _statsP1Out = new();
        private readonly Dictionary<string, long> _statsP2In = new();
        private readonly Dictionary<string, long> _statsP2Out = new();
        private readonly List<Dictionary<string, long>> _allStats = new();
        private readonly Lock _statsLock = new();
        private Dictionary<string, MacEntry> _macTable = new();

        public MainWindow()
        {
            InitializeComponent();
            InitializePorts();
            InitializeStats();
  
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}", ver);
        }

        private void InitializePorts()
        {
            Port1ComboBox.Items.Clear();
            Port2ComboBox.Items.Clear();

            var captureDevices = CaptureDeviceList.Instance;
            foreach (var captureDevice in captureDevices)
            {
                if (captureDevice is not LibPcapLiveDevice live) continue;

                Port1ComboBox.Items.Add(live);
                Port2ComboBox.Items.Add(live);
            }
        }
        
        private void InitializeStats()
        {
            var statNames = new [] {"TOTAL", "Ethernet2", "ARP", "IP", "ICMP", "TCP", "UDP", "HTTP"};
            
            _allStats.AddRange([_statsP1In, _statsP1Out, _statsP2In, _statsP2Out]);

            foreach (var stats in _allStats)
            {
                foreach (var statName in statNames)
                {
                    stats[statName] = 0;
                }
            }
        }

        private void StartCaptureClick(object sender, RoutedEventArgs e)
        {
            if (Port1ComboBox.SelectedItem is not LibPcapLiveDevice port1 ||
                Port2ComboBox.SelectedItem is not LibPcapLiveDevice port2)
                return;

            Port1ComboBox.IsEnabled = false;
            Port2ComboBox.IsEnabled = false;
            StartCaptureButton.IsEnabled = false;

            _port1 = port1;
            _port2 = port2;

            _port1.Open(DeviceModes.Promiscuous, read_timeout: 1000);
            _port2.Open(DeviceModes.Promiscuous, read_timeout: 1000);

            _port1.OnPacketArrival += OnPacketReceived;
            _port2.OnPacketArrival += OnPacketReceived;

            _port1.StartCapture();
            _port2.StartCapture();
        }

        private void StopCaptureClick(object sender, RoutedEventArgs e)
        {
            Port1ComboBox.IsEnabled = true;
            Port2ComboBox.IsEnabled = true;
            StartCaptureButton.IsEnabled = true;

            _port1.OnPacketArrival -= OnPacketReceived;
            _port1.StopCapture();
            _port1.Close();

            _port2.OnPacketArrival -= OnPacketReceived;
            _port2.StopCapture();
            _port2.Close();
        }

        // private static string MakeKey(LibPcapLiveDevice device, ReadOnlySpan<byte> data)
        // {
        //     var hash = MD5.HashData(data);
        //     return device.Name + ":" + Convert.ToHexString(hash);
        // }
        
        private static string MakeKey(LibPcapLiveDevice device, ReadOnlySpan<byte> data)
        {
            var header = data.Slice(0, Math.Min(100, data.Length));  
            var hash = SHA256.HashData(header);
            return Convert.ToHexString(hash);
        }

        private Dictionary<string, long> GetStatsForPort(LibPcapLiveDevice device, bool isIn)
        {
            if (device == _port1 && isIn) return _statsP1In;
            if (device == _port1 && !isIn) return _statsP1Out;
            if (device == _port2 && isIn) return _statsP2In;
            return _statsP2Out;
        }

        private void LearnMAC(Packet packet, int portNumber)
        {
            var agingTime = 180;
            
            var eth = packet.Extract<EthernetPacket>();
            if (eth == null) return;
            
            var srcMac= eth.SourceHardwareAddress.ToString();

            if (_macTable.TryGetValue(srcMac, out var entry)){
                entry.AgingTime = agingTime;
                entry.PortNumber = portNumber;
                
            }
            else
            {
                _macTable[srcMac] = new MacEntry
                {
                    MacAddress = srcMac,
                    PortNumber = portNumber,
                    AgingTime = agingTime
                };
            }
            
        }

        private void ForwardMAC(Packet packet, int portNumber)
        {
            
        }

        private int GetPortNumber(LibPcapLiveDevice port)
        {
            if (port == _port1) return 1;
            if (port == _port2) return 2;
            return -1;
        }

        private void UpdateStats(Dictionary<string, long> stats, Packet packet, bool isPort1, bool isIn)
        {
            lock (_statsLock)
            {
                stats["TOTAL"]++;

                var eth = packet.Extract<EthernetPacket>();
                if (eth != null) stats["Ethernet2"]++;

                var arp = packet.Extract<ArpPacket>();
                if (arp != null) stats["ARP"]++;

                var ipv4 = packet.Extract<IPv4Packet>();
                var ipv6 = packet.Extract<IPv6Packet>();
                if (ipv4 != null || ipv6 != null) stats["IP"]++;

                var icmp4 = packet.Extract<IcmpV4Packet>();
                if (icmp4 != null) stats["ICMP"]++;

                var tcp = packet.Extract<TcpPacket>();
                if (tcp != null)
                {
                    stats["TCP"]++;
                    if (tcp.DestinationPort == 80 || tcp.DestinationPort == 443 ||
                        tcp.SourcePort == 80 || tcp.SourcePort == 443)
                    {
                        stats["HTTP"]++;
                    }
                }
                
                var udp = packet.Extract<UdpPacket>();
                if (udp != null) stats["UDP"]++;
            }

            Dispatcher.BeginInvoke(new Action(() =>
            {
                lock (_statsLock)
                {
                    if (isPort1 && isIn)
                    {
                        P1InTotal.Text = _statsP1In["TOTAL"].ToString();
                        P1InEth.Text = _statsP1In["Ethernet2"].ToString();
                        P1InArp.Text = _statsP1In["ARP"].ToString();
                        P1InIp.Text = _statsP1In["IP"].ToString();
                        P1InIcmp.Text = _statsP1In["ICMP"].ToString();
                        P1InTcp.Text = _statsP1In["TCP"].ToString();
                        P1InUdp.Text = _statsP1In["UDP"].ToString();
                        P1InHttp.Text = _statsP1In["HTTP"].ToString();
                    }
                    else if (isPort1 && !isIn)
                    {
                        P1OutTotal.Text = _statsP1Out["TOTAL"].ToString();
                        P1OutEth.Text = _statsP1Out["Ethernet2"].ToString();
                        P1OutArp.Text = _statsP1Out["ARP"].ToString();
                        P1OutIp.Text = _statsP1Out["IP"].ToString();
                        P1OutIcmp.Text = _statsP1Out["ICMP"].ToString();
                        P1OutTcp.Text = _statsP1Out["TCP"].ToString();
                        P1OutUdp.Text = _statsP1Out["UDP"].ToString();
                        P1OutHttp.Text = _statsP1Out["HTTP"].ToString();
                    }
                    else if (!isPort1 && isIn)
                    {
                        P2InTotal.Text = _statsP2In["TOTAL"].ToString();
                        P2InEth.Text = _statsP2In["Ethernet2"].ToString();
                        P2InArp.Text = _statsP2In["ARP"].ToString();
                        P2InIp.Text = _statsP2In["IP"].ToString();
                        P2InIcmp.Text = _statsP2In["ICMP"].ToString();
                        P2InTcp.Text = _statsP2In["TCP"].ToString();
                        P2InUdp.Text = _statsP2In["UDP"].ToString();
                        P2InHttp.Text = _statsP2In["HTTP"].ToString();
                    }
                    else
                    {
                        P2OutTotal.Text = _statsP2Out["TOTAL"].ToString();
                        P2OutEth.Text = _statsP2Out["Ethernet2"].ToString();
                        P2OutArp.Text = _statsP2Out["ARP"].ToString();
                        P2OutIp.Text = _statsP2Out["IP"].ToString();
                        P2OutIcmp.Text = _statsP2Out["ICMP"].ToString();
                        P2OutTcp.Text = _statsP2Out["TCP"].ToString();
                        P2OutUdp.Text = _statsP2Out["UDP"].ToString();
                        P2OutHttp.Text = _statsP2Out["HTTP"].ToString();
                    }
                }
            }));
        }

        private void OnPacketReceived(object sender, PacketCapture e)
        {
            if (sender is not LibPcapLiveDevice port)
                return;

            var raw = e.GetPacket();
            var data = raw.Data;

            var incomingKey = MakeKey(port, data);

            lock (_recentLock)
            {
                if (_recentSent.Remove(incomingKey))
                {
                    // Console.WriteLine($"Dropped duplicate: {incomingKey}");
                    return;
                }
            }

            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            
            LearnMAC(packet, GetPortNumber(port));
            
            var inStats = GetStatsForPort(port, isIn: true);
            var isPort1 = port == _port1;
            UpdateStats(inStats, packet, isPort1, isIn: true);

            var targetPort = port == _port1 ? _port2 : _port1;

            var outgoingKey = MakeKey(targetPort, data);

            lock (_recentLock)
            {
                _recentSent.Add(outgoingKey);
                _recentOrder.Enqueue(outgoingKey);

                while (_recentOrder.Count > MaxRecent)
                {
                    var oldKey = _recentOrder.Dequeue();
                    _recentSent.Remove(oldKey);
                }
            }
            
            var outStats = GetStatsForPort(targetPort, isIn: false);
            var targetIsPort1 = targetPort == _port1;
            
            UpdateStats(outStats, packet, targetIsPort1, isIn: false);
            targetPort.SendPacket(data);

            // Console.WriteLine($"[{port.Description}] -> [{targetPort.Description}] {data.Length}B");
        }

        private void ResetStatsClick(object sender, RoutedEventArgs e)
        {
            var statNames = new [] {"TOTAL", "Ethernet2", "ARP", "IP", "ICMP", "TCP", "UDP", "HTTP"};

            foreach (var stats in _allStats)
            {
                foreach (var statName in statNames)
                {
                    stats[statName] = 0;
                }
            }
            
            P1InTotal.Text = "0";
            P1InEth.Text = "0";
            P1InArp.Text = "0";
            P1InIp.Text = "0";
            P1InIcmp.Text = "0";
            P1InTcp.Text = "0";
            P1InUdp.Text = "0";
            P1InHttp.Text = "0";

            P1OutTotal.Text = "0";
            P1OutEth.Text = "0";
            P1OutArp.Text = "0";
            P1OutIp.Text = "0";
            P1OutIcmp.Text = "0";
            P1OutTcp.Text = "0";
            P1OutUdp.Text = "0";
            P1OutHttp.Text = "0";

            P2InTotal.Text = "0";
            P2InEth.Text = "0";
            P2InArp.Text = "0";
            P2InIp.Text = "0";
            P2InIcmp.Text = "0";
            P2InTcp.Text = "0";
            P2InUdp.Text = "0";
            P2InHttp.Text = "0";

            P2OutTotal.Text = "0";
            P2OutEth.Text = "0";
            P2OutArp.Text = "0";
            P2OutIp.Text = "0";
            P2OutIcmp.Text = "0";
            P2OutTcp.Text = "0";
            P2OutUdp.Text = "0";
            P2OutHttp.Text = "0";
        }
    }
}
