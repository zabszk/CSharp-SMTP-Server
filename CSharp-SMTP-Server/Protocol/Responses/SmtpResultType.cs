namespace CSharp_SMTP_Server.Protocol.Responses
{
	/// <summary>
	/// Type of SMTP result
	/// </summary>
	public enum SmtpResultType : byte
	{
		/// <summary>
		/// Operation was successful.
		/// </summary>
		Success = 0,
		
		/// <summary>
		/// Operation failed, client should retry later.
		/// </summary>
		TemporaryFail = 1,
		
		/// <summary>
		/// Operation failed and will always fail (eg. invalid address email, limit exceeded). Client should not retry.
		/// </summary>
		PermanentFail = 2
	}
}
