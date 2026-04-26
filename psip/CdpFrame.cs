using System.Text;
using SharpPcap.LibPcap;

namespace psip;

public class CdpFrame
{
    private readonly string _hostname;
    private readonly byte _ttl;

    public CdpFrame(string hostname, int ttl = 180)
    {
        _hostname = hostname;
        _ttl = (byte)Math.Min(ttl, 255);
    }
    
    public List<byte> CreateFrame(LibPcapLiveDevice port, int portNumber)
    {
        List<byte> frame = [];
        
        // Ethernet header
        frame.AddRange([0x01,0x00,0x0C,0xCC,0xCC,0xCC]); // dstMac
        frame.AddRange(port.Interface.MacAddress.GetAddressBytes()); // srcMac
        
        // Length placeholder
        var lengthOffset = frame.Count;
        frame.AddRange([0x00, 0x00]);
        
        // LLC
        frame.AddRange([0xAA, 0xAA, 0x03]);

        // SNAP
        frame.AddRange([0x00, 0x00, 0x0C, 0x20, 0x00]);

        // CDP PDU: version, TTL, checksum (2B placeholder)
        var cdpStart = frame.Count;
        frame.AddRange([0x02, _ttl, 0x00, 0x00]);
        
        var deviceId = BuildTlv(0x0001, Encoding.UTF8.GetBytes(_hostname));
        var portId = BuildTlv(0x0003, Encoding.UTF8.GetBytes("Port" + portNumber));
        var capabilities = BuildTlv(0x0004, new byte[] { 0x00, 0x00, 0x00, 0x08 }); // 0x00000008 - Switch (S)
        var platform = BuildTlv(0x0006, Encoding.UTF8.GetBytes("Software Switch"));
        
        frame.AddRange(deviceId);
        frame.AddRange(portId);
        frame.AddRange(capabilities);
        frame.AddRange(platform);
        
        var payloadLength = (ushort)(frame.Count - lengthOffset - 2);
        frame[lengthOffset] = (byte)(payloadLength >> 8);
        frame[lengthOffset + 1] = (byte)(payloadLength & 0xFF);
        
        var frameArr = frame.ToArray();
        var checksum = ComputeChecksum(frameArr, cdpStart, frameArr.Length - cdpStart);
        frame[cdpStart + 2] = (byte)(checksum >> 8);
        frame[cdpStart + 3] = (byte)(checksum & 0xFF);
        
        return frame;
    }
    
    private static byte[] BuildTlv(ushort type, byte[] data)
    {
        var length = (ushort)(4 + data.Length);
        return
        [
            (byte)(type >> 8), (byte)(type & 0xFF),      // TYPE
            (byte)(length >> 8), (byte)(length & 0xFF),  // LENGTH
            ..data                                       // DATA
        ];
    }
    
    // 1's complement checksum
    private static ushort ComputeChecksum(byte[] data, int offset, int length)
    {
        uint sum = 0;
        for (var i = offset; i < offset + length - 1; i += 2)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
        }
        
        if (length % 2 != 0)
        {
            sum += (uint)(data[offset + length - 1] << 8);
        }

        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
            
        return (ushort)~sum;
    }
}