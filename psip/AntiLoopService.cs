using System.Security.Cryptography;
using SharpPcap.LibPcap;

namespace psip
{
    public class AntiLoopService
    {
        private readonly HashSet<string> _recentSent = new();
        private readonly Queue<string> _recentOrder = new();
        private readonly Lock _recentLock = new();
        private const int MaxRecent = 1000;

        public bool CheckIncoming(ReadOnlySpan<byte> packetData, LibPcapLiveDevice sourcePort)
        {
            var key = MakeKey(packetData, sourcePort.Name);
            
            lock (_recentLock)
            {
                if (_recentSent.Remove(key))
                {
                    return false;
                }
            }
            
            return true;
        }

        public bool CheckOutgoing(ReadOnlySpan<byte> packetData, LibPcapLiveDevice targetPort)
        {
            var key = MakeKey(packetData, targetPort.Name);
            
            lock (_recentLock)
            {
                if (_recentSent.Contains(key))
                {
                    return false;  // drop duplicate
                }
                
                _recentSent.Add(key);
                _recentOrder.Enqueue(key);
                
                while (_recentOrder.Count > MaxRecent)
                {
                    var oldKey = _recentOrder.Dequeue();
                    _recentSent.Remove(oldKey);
                }
                
                return true;  // forward
            }
        }
        
        private static string MakeKey(ReadOnlySpan<byte> data, string portName)
        {
            // var header = data.Slice(0, Math.Min(100, data.Length));
            var hash = SHA256.HashData(data); // change to 100byte header in case of performance issues
            return $"{portName}:{Convert.ToHexString(hash)}";
        }
        
        public void FlushPort(LibPcapLiveDevice port)
        {
            var prefix = port.Name + ":";
    
            lock (_recentLock)
            {
                _recentSent.RemoveWhere(key => key.StartsWith(prefix));
            }
        }
    }
}