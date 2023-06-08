namespace CSharp_SMTP_Server.Networking
{
	/// <summary>
	/// Connection encryption method
	/// </summary>
	public enum ConnectionEncryption : byte
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