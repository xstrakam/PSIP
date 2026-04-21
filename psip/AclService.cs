using PacketDotNet;

namespace psip;

public class AclService
{
    private readonly List<AclRule> _rules = [];
    private readonly Lock _rulesLock = new();
    
    public void AddRule(AclRule rule)
    {
        lock (_rulesLock)
        {
            if (rule.Priority == 0) rule.Priority = _rules.Count == 0 ? 10 : _rules.Max(r => r.Priority) + 10;
            _rules.Add(rule);
        }
    }

    public void RemoveRule(AclRule rule)
    {
        lock (_rulesLock) _rules.Remove(rule);
    }

    public IReadOnlyList<AclRule> GetRules()
    {
        lock (_rulesLock) return _rules.OrderBy(r => r.Priority).ToList();
    }
    
    public bool CheckPacket(Packet packet, int portNumber, bool isIn)
    {
        var srcMac = ExtractSrcMac(packet);
        var dstMac = ExtractDstMac(packet);
        var srcIp = ExtractSrcIp(packet);
        var dstIp = ExtractDstIp(packet);
        var srcPort = ExtractSrcPort(packet);
        var dstPort = ExtractDstPort(packet);
        var icmpType = ExtractIcmpType(packet);
        
        lock (_rulesLock)
        {
            foreach (var rule in _rules.OrderBy(r => r.Priority))
            {
                if (!MatchesDirection(rule, isIn)) continue;
                if (!MatchesPort(rule, portNumber)) continue;
                if (!MatchesProtocol(rule, packet)) continue;
                if (!MatchesSrcMac(rule, srcMac)) continue;
                if (!MatchesDstMac(rule, dstMac)) continue;
                if (!MatchesSrcIp(rule, srcIp)) continue;
                if (!MatchesDstIp(rule, dstIp)) continue;
                if (!MatchesSrcPort(rule, srcPort)) continue;
                if (!MatchesDstPort(rule, dstPort)) continue;
                if (!MatchesIcmpType(rule, icmpType)) continue;
                
                return rule.Action != AclAction.Deny;
            }
            
            return _rules.Count == 0; // implicit deny len, ak je aspon 1 acl pravidlo
        }
    }
    
    private static bool MatchesDirection(AclRule rule, bool isIn)
    {
        if (rule.Direction == AclDirection.Any) return true;
        return isIn && rule.Direction == AclDirection.In || !isIn && rule.Direction == AclDirection.Out;
    }
    
    private static bool MatchesPort(AclRule rule, int portNumber)
    {
        return rule.Port == "any" || rule.Port == portNumber.ToString();
    }

    private static bool MatchesProtocol(AclRule rule, Packet packet)
    {
        return rule.Protocol switch
        {
            AclProtocol.Any => true,
            AclProtocol.Ip => packet.Extract<IPv4Packet>() != null,
            AclProtocol.Icmp => packet.Extract<IcmpV4Packet>() != null,
            AclProtocol.Tcp => packet.Extract<TcpPacket>() != null,
            AclProtocol.Udp => packet.Extract<UdpPacket>() != null,
            _ => true
        };
    }

    private static bool MatchesSrcMac(AclRule rule, string srcMac)
    {
        if (rule.SrcMac == "any") return true;
        return rule.SrcMac == srcMac;
    }
    
    private static bool MatchesDstMac(AclRule rule, string dstMac)
    {   
        if (rule.DstMac == "any") return true;
        return rule.DstMac == dstMac;
    }

    private static bool MatchesSrcIp(AclRule rule, string srcIp)
    {   
        if (rule.SrcIp == "any") return true;
        return MatchesIp(rule.SrcIp, srcIp);
    }
    
    private static bool MatchesDstIp(AclRule rule, string dstIp)
    {
        if (rule.DstIp == "any") return true;
        return MatchesIp(rule.DstIp, dstIp);
    }
    
    private static bool MatchesIp(string aclIp, string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;

        var parts = aclIp.Split('/');

        if (!int.TryParse(parts[1], out var prefixLen)) return false;

        var addrBytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
        var netBytes  = System.Net.IPAddress.Parse(parts[0]).GetAddressBytes();
        
        var fullBytes  = prefixLen / 8;
        var remainBits = prefixLen % 8;

        for (var i = 0; i < fullBytes; i++)
            if (addrBytes[i] != netBytes[i]) return false;
        
        if (remainBits > 0)
        {
            var mask = 0xFF << (8 - remainBits) & 0xFF;
            if ((addrBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }

    private static bool MatchesSrcPort(AclRule rule, int srcPort)
    {
        if (rule.SrcPort == "any") return true;
        return rule.SrcPort == srcPort.ToString();
    }

    private static bool MatchesDstPort(AclRule rule, int dstPort)
    {
        if (rule.DstPort == "any") return true;
        return rule.DstPort == dstPort.ToString();
    }

    private static bool MatchesIcmpType(AclRule rule, AclIcmpType icmpType)
    {
        if (rule.IcmpType == AclIcmpType.Any) return true;
        return rule.IcmpType == icmpType;
    }

    private static string ExtractSrcMac(Packet p)
    {
        return p.Extract<EthernetPacket>()?.SourceHardwareAddress.ToString().ToUpper() ?? "";
    }
    
    private static string ExtractDstMac(Packet p)
    {
        return p.Extract<EthernetPacket>()?.DestinationHardwareAddress.ToString().ToUpper() ?? "";
    }

    private static string ExtractSrcIp(Packet p)
    {
        return p.Extract<IPv4Packet>()?.SourceAddress.ToString() ?? "";
    }

    private static string ExtractDstIp(Packet p)
    {
        return p.Extract<IPv4Packet>()?.DestinationAddress.ToString() ?? "";
    }
    
    private static int ExtractSrcPort(Packet p)
    {
        return p.Extract<TcpPacket>()?.SourcePort ?? p.Extract<UdpPacket>()?.SourcePort ?? 0;
    }
    
    private static int ExtractDstPort(Packet p)
    {
        return p.Extract<TcpPacket>()?.DestinationPort ?? p.Extract<UdpPacket>()?.DestinationPort ?? 0;
    }
    
    private static AclIcmpType ExtractIcmpType(Packet p)
    {
        var icmp = p.Extract<IcmpV4Packet>();
        if (icmp == null) return AclIcmpType.Any;
        return icmp.TypeCode switch
        {
            IcmpV4TypeCode.EchoRequest => AclIcmpType.Echo,
            IcmpV4TypeCode.EchoReply => AclIcmpType.EchoReply,
            _ => AclIcmpType.Any
        };
    }
}