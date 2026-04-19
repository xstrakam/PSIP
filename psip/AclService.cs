using PacketDotNet;

namespace psip;

public class AclService
{
    private readonly List<AclRule> _rules = [];
    private Lock _rulesLock = new Lock();

    public bool CheckPacket(Packet packet, int portNumber, bool isIn)
    {
        var srcMac = ExtractSrcMac(packet);
        var dstMac = ExtractDstMac(packet);
        var srcIp = ExtractSrcIp(packet);
        var dstIp = ExtractDstIp(packet);
        var srcPort = ExtractSrcPort(packet);
        var dstPort = ExtractDstPort(packet);
        
        lock (_rulesLock)
        {
            foreach (var rule in _rules)
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
                if (!MatchesIcmpType(rule, "any")) continue;
                
                return rule.Action != AclAction.Deny;
            }
        }
        
        return false;
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
        return false;
    }
    
    private static bool MatchesDstIp(AclRule rule, string dstIp)
    {
        if (rule.DstIp == "any") return true;
        return false;
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

    private static bool MatchesIcmpType(AclRule rule, string icmpType)
    {
        if (rule.IcmpType == AclIcmpType.Any) return true;
        return rule.IcmpType == AclIcmpType.Echo && icmpType == "Echo" || rule.IcmpType == AclIcmpType.EchoReply && icmpType == "EchoReply";
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
}