using System.Net;
using System.Security.Authentication;
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable ConvertToConstant.Global

namespace CSharp_SMTP_Server.Config
{
	/// <summary>
	/// Options of the <see cref="SMTPServer"/>
	/// </summary>
	public class ServerOptions
	{
		/// <summary>
		/// Server name, sent on connection
		/// </summary>
		public string ServerName = "CSharp SMTP Server";

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
		/// Maximum characters accepted in one SMTP line, including commands and message data lines.
		/// Default: 1000
		/// </summary>
		public uint LineCharactersLimit = 1000;

		/// <summary>
		/// Maximum time to wait for TLS negotiation or the next complete SMTP line, in milliseconds.
		/// Set to 0 to disable the timeout. Default: 120000
		/// </summary>
		public uint ClientIdleTimeout = 120000;

		/// <summary>
		/// Maximum simultaneous clients per listener. Set to 0 to disable the limit. Default: 1000
		/// </summary>
		public uint MaximumConcurrentClients = 1000;

		/// <summary>
		/// Recipients limit per message.
		/// Set to 0 to disable.
		/// Default: 50
		/// </summary>
		public uint RecipientsLimit = 50;

		/// <summary>
		/// Maximum length of email address.
		/// Default: 256
		/// </summary>
		public uint EmailAddressMaximumLength = 256;

		/// <summary>
		/// Maximum length of internet domain.
		/// Default: 255
		/// </summary>
		public uint InternetDomainNameMaximumLength = 255;

		/// <summary>
		/// Configuration of email authentication.
		/// </summary>
		public readonly MailAuthenticationOptions MailAuthenticationOptions;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="mailAuthenticationOptions">Configures the email authentication</param>
		// ReSharper disable InconsistentNaming
		public ServerOptions(MailAuthenticationOptions? mailAuthenticationOptions = null)
		{
			MailAuthenticationOptions = mailAuthenticationOptions ?? new();
		}
	}
}
