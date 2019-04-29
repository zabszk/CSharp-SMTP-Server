namespace CSharp_SMTP_Server.Protocol.Responses
{
	public struct SmtpResult
	{
		public SmtpResult(SmtpResultType type)
		{
			Type = type;
			FailMessage = string.Empty;
		}

		public SmtpResult(SmtpResultType type, string failMessage)
		{
			Type = type;
			FailMessage = failMessage;
		}

		public SmtpResultType Type;
		public string FailMessage;
	}
}
