namespace CSharp_SMTP_Server.Protocol.Responses
{
	/// <summary>
	/// Smtp operation result.
	/// </summary>
	public struct SmtpResult
	{
		/// <summary>
		/// Initializes new instance.
		/// </summary>
		/// <param name="type">Response type.</param>
		/// <param name="failMessage">Custom message. Ignored if type is set to Success.</param>
		public SmtpResult(SmtpResultType type, string? failMessage = null)
		{
			Type = type;
			FailMessage = failMessage;
		}

		/// <summary>
		/// Response type.
		/// </summary>
		public readonly SmtpResultType Type;

		/// <summary>
		/// Custom message.
		/// Ignored if Type is set to Success.
		/// </summary>
		public readonly string? FailMessage;
	}
}