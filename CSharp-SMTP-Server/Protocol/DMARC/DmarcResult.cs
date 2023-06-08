namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// DMARC validation result as defined in RFC 7489
/// </summary>
public enum DmarcResult
{
#pragma warning disable CS1591
	None,
	Quarantine,
	Reject
#pragma warning restore CS1591
}