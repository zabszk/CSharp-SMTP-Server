namespace CSharp_SMTP_Server.Networking
{
    public enum ConnectionEncryption
	{
		/// <summary>
		/// No encryption
		/// </summary>
		Plaintext = 0,
		/// <summary>
		/// StartTLS encryption
		/// </summary>
		StartTls = 1,
		/// <summary>
		/// Connected to encrypted port
		/// </summary>
		Tls = 2
	}
}
