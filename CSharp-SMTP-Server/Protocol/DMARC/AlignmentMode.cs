namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// DMARC alignment mode as defined in RFC 7489
/// </summary>
public enum AlignmentMode
{
	/// <summary>
	/// Relaxed mode
	/// </summary>
	Relaxed,

	/// <summary>
	/// Strict mode
	/// </summary>
	Strict
}