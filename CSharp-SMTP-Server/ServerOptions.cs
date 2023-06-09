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
		/// URL of list of all public suffixes of domains
		/// </summary>
		public string PublicSuffixList = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat";

		/// <summary>
		/// Enables or disables SPF validation of emails sent by unauthenticated users.
		/// Default: true
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool ValidateSPF
		{
			get => _validateSPF;

			set
			{
				if (!value)
				{
					_validateSPF = false;
					return;
				}

				if (DnsServerEndpoint == null)
					throw new Exception("SPF validation can't be enabled if DNS endpoint is not defined!");

				_validateSPF = true;
			}
		}

		/// <summary>
		/// Enables or disables DMARC validation of emails sent by unauthenticated users.
		/// Default: true
		/// </summary>
		// ReSharper disable once InconsistentNaming
		public bool ValidateDMARC
		{
			get => _validateDMARC;

			set
			{
				if (!value)
				{
					_validateDMARC = false;
					return;
				}

				if (DnsServerEndpoint == null)
					throw new Exception("DMARC validation can't be enabled if DNS endpoint is not defined!");

				_validateDMARC = true;
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
		/// <param name="validateSPF">Indicates whether SPF validation should be enabled</param>
		/// <param name="validateDMARC">Indicates whether DMARC validation should be enabled</param>
		/// <param name="dnsServerEndpoint">Specifies DNS server endpoint</param>
		// ReSharper disable InconsistentNaming
		public ServerOptions(bool validateSPF = true, bool validateDMARC = true, EndPoint? dnsServerEndpoint = null)
		{
			_validateSPF = validateSPF;
			_validateDMARC = validateDMARC;
			DnsServerEndpoint = dnsServerEndpoint;

			if ((validateSPF || validateDMARC) && DnsServerEndpoint == null)
				DnsServerEndpoint = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
		}

		// ReSharper disable once InconsistentNaming
		private bool _validateSPF;

		// ReSharper disable once InconsistentNaming
		private bool _validateDMARC;
	}
}