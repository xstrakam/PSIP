using System.Collections.Concurrent;
using System.Text;
using SharpPcap.LibPcap;

namespace psip;

public class CdpNeighbor
{
    public string DeviceId { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemotePort { get; set; } = "";
    public int HoldTime { get; set; }
}

public class CdpService
{
    private readonly ConcurrentDictionary<string, CdpNeighbor> _neighbors = new();
    private System.Timers.Timer? _sendTimer;

    public bool IsRunning { get; private set; }
    public string Hostname { get; set; } = Environment.MachineName;
    public int SendInterval { get; set; } = 60; 
    public int HoldTime { get; set; } = 180;    

    public void Start(List<LibPcapLiveDevice> ports)
    {
        if (IsRunning) return;
        IsRunning = true;

        SendCdpFrames(ports);

        _sendTimer = new System.Timers.Timer(SendInterval * 1000);
        _sendTimer.Elapsed += (_, _) => SendCdpFrames(ports);
        _sendTimer.AutoReset = true;
        _sendTimer.Start();
    }

    public void Stop()
    {
        _sendTimer?.Stop();
        _sendTimer = null;
        IsRunning = false;
    }

    public void TickAging()
    {
        foreach (var key in _neighbors.Keys)
        {
            if (_neighbors.TryGetValue(key, out var neighbor))
            {
                neighbor.HoldTime--;
                if (neighbor.HoldTime <= 0)
                    _neighbors.TryRemove(key, out _);
            }
        }
    }
    
    public void ParseFrame(byte[] payload, int portNumber)
    {
        if (payload.Length < 8) return;
        if (payload[0] != 0xAA || payload[1] != 0xAA || payload[2] != 0x03) return;
        if (payload[3] != 0x00 || payload[4] != 0x00 || payload[5] != 0x0C) return;
        if (payload[6] != 0x20 || payload[7] != 0x00) return;

        // CDP PDU
        const int cdpOffset = 8;
        if (payload.Length < cdpOffset + 4) return;

        int ttl = payload[cdpOffset + 1];
        var tlvOffset = cdpOffset + 4;

        var neighbor = new CdpNeighbor
        {
            LocalPort = portNumber,
            HoldTime = ttl
        };

        while (tlvOffset + 4 <= payload.Length)
        {
            var type = (ushort)((payload[tlvOffset] << 8) | payload[tlvOffset + 1]);
            var length = (ushort)((payload[tlvOffset + 2] << 8) | payload[tlvOffset + 3]);

            if (length < 4 || tlvOffset + length > payload.Length) break;

            var data = payload[(tlvOffset + 4)..(tlvOffset + length)];

            switch (type)
            {
                case 0x0001:
                    neighbor.DeviceId = Encoding.UTF8.GetString(data);
                    break;
                case 0x0003:
                    neighbor.RemotePort = Encoding.UTF8.GetString(data);
                    break;
            }

            tlvOffset += length;
        }

        if (string.IsNullOrEmpty(neighbor.DeviceId)) return;
        
        if (neighbor.DeviceId == Hostname) return; // aby v cdp table neukazovalo tento switch

        _neighbors.AddOrUpdate(neighbor.DeviceId, neighbor, (_, existing) =>
        {
            existing.HoldTime = neighbor.HoldTime;
            existing.RemotePort = neighbor.RemotePort;
            existing.LocalPort = neighbor.LocalPort;
            return existing;
        });
    }
    
    private void SendCdpFrames(List<LibPcapLiveDevice> ports)
    {
        foreach (var port in ports.ToList())
        {
            try
            {
                var portNumber = ports.IndexOf(port) + 1;
                var builder = new CdpFrame(Hostname, HoldTime);
                var frame = builder.CreateFrame(port, portNumber);
                port.SendPacket(frame.ToArray());
            }
            catch { }
        }
    }

    public List<CdpNeighbor> GetNeighbors()
    {
        return _neighbors.Values.ToList();
    }
    
}