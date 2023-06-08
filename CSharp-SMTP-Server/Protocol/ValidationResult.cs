namespace CSharp_SMTP_Server.Protocol;

/// <summary>
/// SPF or DMARC validation result
/// </summary>
public enum ValidationResult
{
#pragma warning disable CS1591
	None,
	Neutral,
	Pass,
	Fail,
	Softfail,
	Temperror,
	Permerror,
#pragma warning restore CS1591

	/// <summary>
	/// SPF validation is disabled in SMTP server config
	/// </summary>
	CheckDisabled,

	/// <summary>
	/// SPF validation was skipped, because user is authenticated
	/// </summary>
	UserAuthenticated
}