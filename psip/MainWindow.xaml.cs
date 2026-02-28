using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace psip
{
    public class PortDirectionStats
    {
        public long TotalFrames;
        public long Ethernet2;
        public long Ip;
        public long Icmp;
        public long Tcp;
        public long Udp;
    }
    
    public class PortStats
    {
        public PortDirectionStats In { get; } = new();
        public PortDirectionStats Out { get; } = new();
    }

    public partial class MainWindow : Window
    {
        private LibPcapLiveDevice _port1, _port2;

        private readonly HashSet<string> _recentSent = new();
        private readonly Queue<string> _recentOrder = new();
        private readonly object _recentLock = new();
        private const int MaxRecent = 10_000;
        
        private readonly PortStats _statsPort1 = new();
        private readonly PortStats _statsPort2 = new();
        private readonly object _statsLock = new();

        public MainWindow()
        {
            InitializeComponent();
            InitializePorts();

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

        private static string MakeKey(LibPcapLiveDevice dev, ReadOnlySpan<byte> data)
        {
            var hash = MD5.HashData(data);
            return dev.Name + ":" + Convert.ToHexString(hash);
        }

        private PortStats GetStatsForPort(LibPcapLiveDevice dev)
        {
            if (dev == _port1) return _statsPort1;
            if (dev == _port2) return _statsPort2;
            return _statsPort1;
        }

        private void UpdateStats(PortDirectionStats stats, Packet packet, bool isPort1, bool isIn)
        {
            lock (_statsLock)
            {
                stats.TotalFrames++;

                var eth = packet.Extract<EthernetPacket>();
                if (eth != null) stats.Ethernet2++;

                var ipv4 = packet.Extract<IPv4Packet>();
                var ipv6 = packet.Extract<IPv6Packet>();
                if (ipv4 != null || ipv6 != null) stats.Ip++;

                var icmp4 = packet.Extract<IcmpV4Packet>();
                if (icmp4 != null) stats.Icmp++;
                
                var tcp = packet.Extract<TcpPacket>();
                if (tcp != null) stats.Tcp++;

                var udp = packet.Extract<UdpPacket>();
                if (udp != null) stats.Udp++;
                
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (isPort1 && isIn)
                    {
                        P1InTotal.Text = stats.TotalFrames.ToString();
                        P1InEth.Text   = stats.Ethernet2.ToString();
                        P1InIp.Text    = stats.Ip.ToString();
                        P1InIcmp.Text  = stats.Icmp.ToString();
                        P1InTcp.Text   = stats.Tcp.ToString();
                        P1InUdp.Text   = stats.Udp.ToString();
                    }
                    else if (isPort1 && !isIn)
                    {
                        P1OutTotal.Text = stats.TotalFrames.ToString();
                        P1OutEth.Text   = stats.Ethernet2.ToString();
                        P1OutIp.Text    = stats.Ip.ToString();
                        P1OutIcmp.Text  = stats.Icmp.ToString();
                        P1OutTcp.Text   = stats.Tcp.ToString();
                        P1OutUdp.Text   = stats.Udp.ToString();
                    }
                    else if (!isPort1 && isIn)
                    {
                        P2InTotal.Text = stats.TotalFrames.ToString();
                        P2InEth.Text   = stats.Ethernet2.ToString();
                        P2InIp.Text    = stats.Ip.ToString();
                        P2InIcmp.Text  = stats.Icmp.ToString();
                        P2InTcp.Text   = stats.Tcp.ToString();
                        P2InUdp.Text   = stats.Udp.ToString();
                    }
                    else // !isPort1 && !isIn
                    {
                        P2OutTotal.Text = stats.TotalFrames.ToString();
                        P2OutEth.Text   = stats.Ethernet2.ToString();
                        P2OutIp.Text    = stats.Ip.ToString();
                        P2OutIcmp.Text  = stats.Icmp.ToString();
                        P2OutTcp.Text   = stats.Tcp.ToString();
                        P2OutUdp.Text   = stats.Udp.ToString();
                    }
                }));
            }
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
                    return;
            }

            var packet = PacketDotNet.Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            
            var inStats = GetStatsForPort(port).In;
            bool isPort1 = port == _port1;
            UpdateStats(inStats, packet, isPort1, isIn: true);

            var targetPort = port == _port1 ? _port2 : _port1;
            if (targetPort == null)
                return;

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
            
            var outStats = GetStatsForPort(targetPort).Out;
            bool targetIsPort1 = targetPort == _port1;
            UpdateStats(outStats, packet, targetIsPort1, isIn: false);

            targetPort.SendPacket(data);

            Console.WriteLine($"✓ [{port.Description}] → [{targetPort.Description}] {data.Length}B");
        }
    }
}
