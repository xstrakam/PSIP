using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace psip
{
    public class AntiLoopService
    {
        private readonly Dictionary<string, long> _seen = new();
        private readonly Lock _lock = new();
        private const int ExpiryMs = 2000;

        public bool Check(ReadOnlySpan<byte> packetData)
        {
            var hash = MakeHash(packetData);
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            lock (_lock)
            {
                Cleanup(now);

                if (_seen.ContainsKey(hash))
                    return false;

                _seen[hash] = now;
                return true;
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _seen.Clear();
            }
        }

        private void Cleanup(long now)
        {
            var expired = _seen
                .Where(e => now - e.Value > ExpiryMs)
                .Select(e => e.Key)
                .ToList();

            foreach (var key in expired)
                _seen.Remove(key);
        }

        private static string MakeHash(ReadOnlySpan<byte> data)
        {
            return Convert.ToHexString(SHA256.HashData(data));
        }
    }
}