namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// Method used to determine the Organizational Domain during DMARC validation
/// </summary>
public enum OrganizationalDomainDiscovery
{
	/// <summary>
	/// DNS Tree Walk as defined in RFC 9989 (DMARCbis).
	/// Does not require any external list, the Organizational Domain is discovered using DNS queries.
	/// </summary>
	DnsTreeWalk,

	/// <summary>
	/// Public Suffix List as used by RFC 7489.
	/// Requires the list to be downloaded (see <see cref="Config.MailAuthenticationOptions.AutomaticallyDownloadPublicSuffixList"/>) or loaded manually.
	/// </summary>
	PublicSuffixList
}
