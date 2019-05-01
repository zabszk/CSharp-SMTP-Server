using System.Security.Authentication;

namespace CSharp_SMTP_Server
{
	public class ServerOptions
	{
		/// <summary>
		/// Server name, sent on connection
		/// </summary>
		public string ServerName;

		/// <summary>
		/// Requirement of using encryption to authenticate
		/// Default: true
		/// </summary>
		public bool RequireEncryptionForAuth = true;

        /// <summary>
        /// Allowed SSL/TLS protocols.
        /// Default: TLS 1.2
        /// </summary>
        public SslProtocols Protocols = SslProtocols.Tls12;

        /// <summary>
        /// Message characters limit.
        /// Set to 0 to disable the limit.
        /// Default: 10 485 760
        /// </summary>
        public uint MessageCharactersLimit = 10485760;

        /// <summary>
        /// Recipients limit per message.
        /// Set to 0 to disable.
        /// Default: 50
        /// </summary>
        public uint RecipientsLimit = 50;
    }
}
