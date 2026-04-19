using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
using System.Timers;
using System.Windows;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace psip
{
    public class MacEntry
    {
        public string MacAddress { get; init; } = "";
        public int PortNumber { get; set; }
        public int AgingTime { get; set; }
    }

    public partial class MainWindow : Window
    {
        private LibPcapLiveDevice? _port1;
        private LibPcapLiveDevice? _port2;
        private List<LibPcapLiveDevice> _ports = [];

        private string _port1Name = "";
        private string _port2Name = "";

        private int _agingTime = 180;
        private System.Timers.Timer? _agingTimer;
        private System.Timers.Timer? _guiRefreshTimer;

        private readonly Dictionary<string, long> _statsP1In = new();
        private readonly Dictionary<string, long> _statsP1Out = new();
        private readonly Dictionary<string, long> _statsP2In = new();
        private readonly Dictionary<string, long> _statsP2Out = new();

        private readonly List<Dictionary<string, long>> _allStats = [];
        private readonly Lock _statsLock = new();

        private readonly Dictionary<string, MacEntry> _macTable = new();
        private readonly Lock _macTableLock = new();
        private readonly ObservableCollection<MacEntry> _macTableItems = new();

        private readonly AntiLoopService _antiLoop = new();

        private enum PortLinkState { Up, PendingDown, Down }
        private readonly Dictionary<LibPcapLiveDevice, PortLinkState> _linkStates = new();
        private readonly Dictionary<LibPcapLiveDevice, long> _disconnectTimes = new();

        private volatile bool _restartInProgress = false;

        public MainWindow()
        {
            InitializeComponent();

            MacTableDataGrid.ItemsSource = _macTableItems;
            DataContext = this;

            InitializePorts();
            InitializeStats();

            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}", ver);
        }

        private void InitializePorts()
        {
            Port1ComboBox.Items.Clear();
            Port2ComboBox.Items.Clear();

            var captureDevices = CaptureDeviceList.New();
            foreach (var captureDevice in captureDevices)
            {
                if (captureDevice is not LibPcapLiveDevice live) continue;

                Port1ComboBox.Items.Add(live);
                Port2ComboBox.Items.Add(live);
            }
        }

        private void InitializeStats()
        {
            var statNames = new[] { "TOTAL", "Ethernet2", "ARP", "IP", "ICMP", "TCP", "UDP", "HTTP" };

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

            if (port1.Name == port2.Name)
                return;

            Port1ComboBox.IsEnabled = false;
            Port2ComboBox.IsEnabled = false;
            StartCaptureButton.IsEnabled = false;

            _port1 = port1;
            _port2 = port2;
            _port1Name = port1.Name;
            _port2Name = port2.Name;
            _ports = [_port1, _port2];

            OpenPort(_port1);
            OpenPort(_port2);

            _linkStates.Clear();
            _disconnectTimes.Clear();

            foreach (var port in _ports)
            {
                _linkStates[port] = PortLinkState.Up;
            }

            StartAgingTimer();
            StartGuiRefreshTimer();
        }

        private void StopCaptureClick(object sender, RoutedEventArgs e)
        {
            Port1ComboBox.IsEnabled = true;
            Port2ComboBox.IsEnabled = true;
            StartCaptureButton.IsEnabled = true;

            _agingTimer?.Stop();
            _guiRefreshTimer?.Stop();

            StopPortSafely(_port1);
            StopPortSafely(_port2);

            _ports.Clear();
            _linkStates.Clear();
            _disconnectTimes.Clear();
            _antiLoop.Clear();
        }

        private void OpenPort(LibPcapLiveDevice port)
        {
            port.Open(DeviceModes.Promiscuous, read_timeout: 500);
            port.OnPacketArrival -= OnPacketReceived;
            port.OnPacketArrival += OnPacketReceived;
            port.StartCapture();
        }

        private void StopPortSafely(LibPcapLiveDevice? port)
        {
            if (port == null) return;

            try { port.OnPacketArrival -= OnPacketReceived; } catch { }
            try { port.StopCapture(); } catch { }
            try { port.Close(); } catch { }
        }

        private LibPcapLiveDevice OpenPortByName(string deviceName)
        {
            var freshList = CaptureDeviceList.New();

            var port = freshList.OfType<LibPcapLiveDevice>().First(d => d.Name == deviceName);

            OpenPort(port);
            return port;
        }

        private LibPcapLiveDevice RestartPort(LibPcapLiveDevice oldPort)
        {
            var deviceName = oldPort.Name;
            var portNumber = GetPortNumberFromPort(oldPort);

            StopPortSafely(oldPort);

            var newPort = OpenPortByName(deviceName);

            if (portNumber == 1)
                _port1 = newPort;
            else
                _port2 = newPort;

            _ports = [_port1!, _port2!];

            _linkStates.Remove(oldPort);
            _disconnectTimes.Remove(oldPort);
            _linkStates[newPort] = PortLinkState.Up;

            _antiLoop.Clear();

            return newPort;
        }

        private void CheckLinkState(LibPcapLiveDevice port)
        {
            if (_restartInProgress) return;

            var nic = FindNetworkInterface(port);
            if (nic == null) return;

            var isUp = nic.OperationalStatus == OperationalStatus.Up;
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var state = _linkStates.GetValueOrDefault(port, PortLinkState.Up);

            switch (state)
            {
                case PortLinkState.Up when !isUp:
                    _linkStates[port] = PortLinkState.PendingDown;
                    _disconnectTimes[port] = now;
                    break;

                case PortLinkState.PendingDown when isUp:
                    _linkStates[port] = PortLinkState.Up;
                    _disconnectTimes.Remove(port);
                    break;

                case PortLinkState.PendingDown when !isUp:
                {
                    if (!_disconnectTimes.TryGetValue(port, out var downSince))
                        break;

                    if (now - downSince >= 5000)
                    {
                        _linkStates[port] = PortLinkState.Down;
                        _disconnectTimes.Remove(port);
                        ClearMacEntriesByPortNumber(GetPortNumberFromPort(port));
                    }
                    break;
                }

                case PortLinkState.Down when isUp:
                    _restartInProgress = true;
                    try
                    {
                        RestartPort(port);
                    }
                    finally
                    {
                        _restartInProgress = false;
                    }
                    break;
            }
        }

        private void ClearMacTableClick(object sender, RoutedEventArgs e)
        {
            ClearWholeMacTable();
            _antiLoop.Clear();
        }

        private void SetAgingTimeClick(object sender, RoutedEventArgs e)
        {
            if (int.TryParse(AgingTimeTextBox.Text, out var agingTime) && agingTime > 0)
            {
                _agingTime = agingTime;
                AgingTimeTextBox.Text = "";
            }
        }

        private void StartAgingTimer()
        {
            _agingTimer?.Stop();
            _agingTimer = new System.Timers.Timer(1000);
            _agingTimer.Elapsed += OnAgingTick;
            _agingTimer.AutoReset = true;
            _agingTimer.Start();
        }

        private void StartGuiRefreshTimer()
        {
            _guiRefreshTimer?.Stop();
            _guiRefreshTimer = new System.Timers.Timer(100);
            _guiRefreshTimer.Elapsed += OnGuiRefreshTick;
            _guiRefreshTimer.AutoReset = true;
            _guiRefreshTimer.Start();
        }

        private Dictionary<string, long> GetStatsForPort(LibPcapLiveDevice device, bool isIn)
        {
            if (_port1 != null && device == _port1 && isIn) return _statsP1In;
            if (_port1 != null && device == _port1 && !isIn) return _statsP1Out;
            if (_port2 != null && device == _port2 && isIn) return _statsP2In;
            return _statsP2Out;
        }

        private void LearnMac(Packet packet, LibPcapLiveDevice port)
        {
            UpdateStats(packet, port, true);

            var eth = packet.Extract<EthernetPacket>();
            if (eth == null) return;

            var srcMac = eth.SourceHardwareAddress.ToString();
            var srcMacFormatted = string.Join(":", srcMac.Chunk(2).Select(c => new string(c)));
            var portNumber = GetPortNumberFromPort(port);

            lock (_macTableLock)
            {
                if (_macTable.TryGetValue(srcMac, out var entry))
                {
                    entry.AgingTime = _agingTime;
                    entry.PortNumber = portNumber;
                }
                else
                {
                    _macTable[srcMac] = new MacEntry
                    {
                        MacAddress = srcMacFormatted,
                        PortNumber = portNumber,
                        AgingTime = _agingTime
                    };
                }
            }
        }

        private void ForwardMac(Packet packet, ReadOnlySpan<byte> data, LibPcapLiveDevice srcPort)
        {
            var eth = packet.Extract<EthernetPacket>();
            if (eth == null) return;

            var destMac = eth.DestinationHardwareAddress.ToString().ToUpper();

            if (destMac == "FFFFFFFFFFFF")
            {
                SendUnknownUnicast(packet, data, srcPort);
                return;
            }

            lock (_macTableLock)
            {
                if (_macTable.TryGetValue(destMac, out var entry))
                {
                    if (entry.PortNumber != GetPortNumberFromPort(srcPort))
                    {
                        var destPort = GetPortFromPortNumber(entry.PortNumber);
                        if (destPort != null)
                            SendUnicast(packet, data, destPort);
                    }
                }
                else
                {
                    SendUnknownUnicast(packet, data, srcPort);
                }
            }
        }

        private void SendUnknownUnicast(Packet packet, ReadOnlySpan<byte> data, LibPcapLiveDevice excludedPort)
        {
            foreach (var port in _ports.ToList())
            {
                if (port == excludedPort) continue;

                try
                {
                    port.SendPacket(data);
                    UpdateStats(packet, port, false);
                }
                catch (Exception ex)
                {
                    // Console.WriteLine($"SendUnknownUnicast failed on {port.Name}: {ex.Message}");
                }
            }
        }

        private void SendUnicast(Packet packet, ReadOnlySpan<byte> data, LibPcapLiveDevice destPort)
        {
            try
            {
                destPort.SendPacket(data);
                UpdateStats(packet, destPort, false);
            }
            catch (Exception ex)
            {
                // Console.WriteLine($"SendUnicast failed on {destPort.Name}: {ex.Message}");
            }
        }

        private static string? ExtractGuidFromDeviceName(string deviceName)
        {
            var match = Regex.Match(deviceName, @"\{([A-Fa-f0-9\-]+)\}");
            return match.Success ? match.Groups[1].Value : null;
        }

        private static string NormalizeGuid(string guid)
        {
            return guid.Trim('{', '}').ToUpperInvariant();
        }

        private static NetworkInterface? FindNetworkInterface(LibPcapLiveDevice port)
        {
            var guid = ExtractGuidFromDeviceName(port.Name);
            if (guid == null) return null;

            var normalizedGuid = NormalizeGuid(guid);

            return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => NormalizeGuid(n.Id) == normalizedGuid);
        }

        private void ClearWholeMacTable()
        {
            lock (_macTableLock)
            {
                _macTable.Clear();
            }
        }

        private void ClearMacEntriesByPortNumber(int portNumber)
        {
            List<string> toRemove = [];

            lock (_macTableLock)
            {
                foreach (var entry in _macTable)
                {
                    if (entry.Value.PortNumber == portNumber)
                        toRemove.Add(entry.Key);
                }

                foreach (var key in toRemove)
                {
                    _macTable.Remove(key);
                }
            }
        }

        private int GetPortNumberFromPort(LibPcapLiveDevice port)
        {
            if (_port1 != null && port == _port1) return 1;
            return 2;
        }

        private LibPcapLiveDevice? GetPortFromPortNumber(int portNumber)
        {
            return portNumber == 1 ? _port1 : _port2;
        }

        private void OnPacketReceived(object sender, PacketCapture e)
        {
            if (_restartInProgress) return;
            if (sender is not LibPcapLiveDevice port) return;

            try
            {
                var raw = e.GetPacket();
                var data = raw.Data;

                if (!_antiLoop.Check(data))
                    return;

                var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

                LearnMac(packet, port);
                ForwardMac(packet, data, port);
            }
            catch (Exception ex)
            {
                // Console.WriteLine($"OnPacketReceived failed: {ex.Message}");
            }
        }

        private void OnAgingTick(object? sender, ElapsedEventArgs e)
        {
            foreach (var port in _ports.ToList())
            {
                CheckLinkState(port);
            }

            lock (_macTableLock)
            {
                List<string> toRemove = [];

                foreach (var entry in _macTable)
                {
                    entry.Value.AgingTime--;

                    if (entry.Value.AgingTime <= 0)
                        toRemove.Add(entry.Key);
                }

                foreach (var key in toRemove)
                {
                    _macTable.Remove(key);
                }
            }
        }

        private void OnGuiRefreshTick(object? sender, ElapsedEventArgs e)
        {
            List<MacEntry> snapshot;
            lock (_macTableLock)
            {
                snapshot = _macTable.Values
                    .Select(x => new MacEntry
                    {
                        MacAddress = x.MacAddress,
                        PortNumber = x.PortNumber,
                        AgingTime = x.AgingTime
                    })
                    .ToList();
            }

            Dispatcher.BeginInvoke(() =>
            {
                _macTableItems.Clear();
                foreach (var entry in snapshot)
                {
                    _macTableItems.Add(entry);
                }
            });
        }

        private void UpdateStats(Packet packet, LibPcapLiveDevice port, bool isIn)
        {
            lock (_statsLock)
            {
                var stats = GetStatsForPort(port, isIn);
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
                    var portNumber = GetPortNumberFromPort(port);
                    var isPort1 = portNumber == 1;

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

        private void ResetStatsClick(object sender, RoutedEventArgs e)
        {
            var statNames = new[] { "TOTAL", "Ethernet2", "ARP", "IP", "ICMP", "TCP", "UDP", "HTTP" };

            lock (_statsLock)
            {
                foreach (var stats in _allStats)
                {
                    foreach (var statName in statNames)
                    {
                        stats[statName] = 0;
                    }
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