namespace CSharp_SMTP_Server.Protocol.SPF;

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