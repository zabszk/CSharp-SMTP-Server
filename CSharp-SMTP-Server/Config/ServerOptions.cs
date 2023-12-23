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
		/// Recipients limit per message.
		/// Set to 0 to disable.
		/// Default: 50
		/// </summary>
		public uint RecipientsLimit = 50;

		/// <summary>
		/// Configuration of email authentication.
		/// </summary>
		public readonly MailAuthenticationOptions MailAuthenticationOptions;

		/// <summary>
		/// Endpoint to the DNS Server used for SPF validation.
		/// Default: 1.1.1.1:53 (Cloudflare Public DNS Server)
		/// </summary>
		public readonly EndPoint? DnsServerEndpoint;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="dnsServerEndpoint">Specifies DNS server endpoint</param>
		/// <param name="mailAuthenticationOptions">Configures the email authentication</param>
		// ReSharper disable InconsistentNaming
		public ServerOptions(EndPoint? dnsServerEndpoint = null, MailAuthenticationOptions? mailAuthenticationOptions = null)
		{
			DnsServerEndpoint = dnsServerEndpoint;
			MailAuthenticationOptions = mailAuthenticationOptions ?? new();

			if (MailAuthenticationOptions.AnyMechanismEnabled)
				DnsServerEndpoint = dnsServerEndpoint ?? new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
		}
	}
}