using System.Windows;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace psip;


public partial class MainWindow : Window
{
    private LibPcapLiveDevice _port1, _port2;
    
    public MainWindow()
    {
        InitializeComponent();
        InitializePorts();
    }

    private void InitializePorts()
    {
        Port1ComboBox.Items.Clear();
        Port2ComboBox.Items.Clear();
        
        var captureDevices = CaptureDeviceList.Instance;
        foreach (var captureDevice in captureDevices)
        {
            if (captureDevice is not LibPcapLiveDevice) continue;
            Port1ComboBox.Items.Add(captureDevice);
            Port2ComboBox.Items.Add(captureDevice);

        }
    }
    
    private void StartCaptureClick(object sender, RoutedEventArgs e)
    {
        if (Port1ComboBox.SelectedItem is not LibPcapLiveDevice port1 ||
            Port2ComboBox.SelectedItem is not LibPcapLiveDevice port2) return;
        
        Port1ComboBox.IsEnabled = false;
        Port2ComboBox.IsEnabled = false;
        StartCaptureButton.IsEnabled = false;
        
        _port1 = port1;
        _port2 = port2;
        
        _port1.Open(DeviceModes.Promiscuous, 1000);  // ← Promiscuous!
        _port2.Open(DeviceModes.Promiscuous, 1000);
    
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
        
        _port1.StopCapture(); 
        _port2.StopCapture(); 
        
        _port1.Close();
        _port2.Close();
    }

    private void OnPacketReceived(object sender, PacketCapture e)
    {
        var port = (LibPcapLiveDevice)sender;
        var raw = e.GetPacket();
        var targetPort = port == _port1 ? _port2 : _port1;
        
        var eth = Packet.ParsePacket(port.LinkType, raw.Data)?.Extract<EthernetPacket>();
        
        targetPort.SendPacket(raw.Data);
        Console.WriteLine($"[{port.Description}] → [{targetPort.Description}] {raw.Data.Length} bytes");
    }
}