using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace psip
{
    public partial class MainWindow : Window
    {
        private LibPcapLiveDevice _port1, _port2;
        
        private readonly HashSet<string> _recentSent = new();
        private readonly Queue<string> _recentOrder = new();
        private readonly object _recentLock = new();
        private const int MaxRecent = 10_000;

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
                    return;
                }
            }
            
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

            targetPort.SendPacket(data);

            Console.WriteLine($"✓ [{port.Description}] → [{targetPort.Description}] {data.Length}B");
        }
    }
}
