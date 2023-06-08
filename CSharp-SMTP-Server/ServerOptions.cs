using System;
using System.Net;
using System.Security.Authentication;
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable ConvertToConstant.Global

namespace CSharp_SMTP_Server
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
		/// Enables or disables SPF validation of emails sent by unauthenticated users.
		/// Default: true
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool ValidateSPF
		{
			get => _validateSpf;

			set
			{
				if (!value)
				{
					_validateSpf = false;
					return;
				}

				if (DnsServerEndpoint == null)
					throw new Exception("SPF Validation can't be enabled if DNS endpoint is not defined!");

				_validateSpf = true;
			}
		}

		/// <summary>
		/// Endpoint to the DNS Server used for SPF validation.
		/// Default: 1.1.1.1:53 (Cloudflare Public DNS Server)
		/// </summary>
		public readonly EndPoint? DnsServerEndpoint;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="validateSpf">Indicates whether SPF validation should be enabled</param>
		/// <param name="dnsServerEndpoint">Specifies DNS server endpoint</param>
		public ServerOptions(bool validateSpf = true, EndPoint? dnsServerEndpoint = null)
		{
			_validateSpf = validateSpf;
			DnsServerEndpoint = dnsServerEndpoint;

			if (validateSpf && DnsServerEndpoint == null)
				DnsServerEndpoint = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
		}

		private bool _validateSpf;
	}
}