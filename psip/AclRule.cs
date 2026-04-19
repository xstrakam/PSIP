using SharpPcap.LibPcap;

namespace psip;

public enum AclDirection {In, Out, Any}
public enum AclProtocol {Ip, Icmp, Tcp, Udp, Any}
public enum AclIcmpType {Echo, EchoReply, Any}
public enum AclAction {Permit, Deny}

public class AclRule
{
    public int Priority { get; set; }
    public AclDirection Direction { get; set; } = AclDirection.Any;
    public string Port { get; set; } = "any";
    public AclProtocol Protocol { get; set; } =  AclProtocol.Any;
    public string SrcMac { get; set; } = "any";
    public string DstMac { get; set; } = "any";
    public string SrcIp { get; set; } = "any";
    public string DstIp { get; set; } = "any";
    public string SrcPort { get; set; } = "any";
    public string DstPort { get; set; } = "any";
    public AclIcmpType IcmpType { get; set; } = AclIcmpType.Any;
    public AclAction Action { get; set; } = AclAction.Deny;
}