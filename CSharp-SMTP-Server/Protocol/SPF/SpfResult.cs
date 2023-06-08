namespace CSharp_SMTP_Server.Protocol.SPF;

/// <summary>
/// SPF validation result
/// </summary>
public enum SpfResult
{
	None,
	Neutral,
	Pass,
	Fail,
	Softfail,
	Temperror,
	Permerror
}