﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol;
using CSharp_SMTP_Server.Protocol.SPF;
using CSharp_SMTP_Server.Protocol.DMARC;
using DnsClient;

namespace CSharp_SMTP_Server
{
	/// <summary>
	/// Instance of the SMTP server
	/// </summary>
	// ReSharper disable once InconsistentNaming
	// ReSharper disable once ClassNeverInstantiated.Global
	public class SMTPServer : IDisposable
	{
		/// <summary>
		/// Library version
		/// </summary>
		public const string VersionString = "1.1.6";

		/// <summary>
		/// Server options
		/// </summary>
		public readonly ServerOptions Options;

		/// <summary>
		/// DNS Client used for email messages authentication
		/// </summary>
		public readonly DnsClient.DnsClient? DnsClient;

		/// <summary>
		/// SPF validator
		/// </summary>
		public readonly SpfValidator? SpfValidator;

		/// <summary>
		/// DMARC validator
		/// </summary>
		public readonly DmarcValidator? DmarcValidator;

		internal readonly IMailDelivery MailDeliveryInterface;

		internal IAuthLogin? AuthLogin { get; private set; }

		internal IMailFilter? Filter { get; private set; }

		internal readonly ILogger? LoggerInterface;

		internal X509Certificate? Certificate { get; private set; }

		private readonly List<Listener> _listeners = new();

		private bool _started;

		/// <summary>
		/// Initializes the instance of SMTP server with TLS certificate.
		/// </summary>
		/// <param name="parameters">Listening parameters</param>
		/// <param name="options">Server options</param>
		/// <param name="deliveryInterface">Interface used for email delivery.</param>
		/// <param name="loggerInterface">Interface used for logging server errors.</param>
		/// <param name="certificate">TLS certificate of the server.</param>
		public SMTPServer(IEnumerable<ListeningParameters>? parameters, ServerOptions? options,
			IMailDelivery deliveryInterface, ILogger? loggerInterface = null,
			X509Certificate? certificate = null)
		{
			Options = options ?? new();
			MailDeliveryInterface = deliveryInterface;
			LoggerInterface = loggerInterface;
			Certificate = certificate;

			if (Options.DnsServerEndpoint != null)
			{
				DnsClient = new DnsClient.DnsClient(Options.DnsServerEndpoint, new DnsClientOptions {ErrorLogging = new DnsLogger(this)});
				SpfValidator = new SpfValidator(this);
				DmarcValidator = new DmarcValidator(this);
			}

			if (parameters != null)
				foreach (var parameter in parameters)
				{
					if (parameter == null)
						continue;

					if (parameter.RegularPorts != null)
						foreach (var port in parameter.RegularPorts)
							_listeners.Add(new Listener(parameter.IpAddress, port, this, false, parameter.DualMode));

					if (parameter.TlsPorts != null)
						foreach (var port in parameter.TlsPorts)
							_listeners.Add(new Listener(parameter.IpAddress, port, this, true, parameter.DualMode));
				}
		}

		/// <summary>
		/// Starts the server.
		/// </summary>
		public void Start()
		{
			_started = true;
			_listeners.ForEach(listener => listener.Start());
		}

		/// <summary>
		/// Stops and disposes the server.
		/// </summary>
		public void Dispose()
		{
			LoggerInterface?.LogError($"SMTP Server Dispose() called. Stack trace: {new System.Diagnostics.StackTrace()}");
			GC.SuppressFinalize(this);

			foreach (var listener in _listeners)
				listener.Dispose();

			Certificate?.Dispose();
		}

		/// <summary>
		/// Sets the interface used for authentication. Enables authentication if not null.
		/// </summary>
		/// <param name="authInterface"></param>
		public void SetAuthLogin(IAuthLogin? authInterface) => AuthLogin = authInterface;

		/// <summary>
		/// Sets the email filter.
		/// </summary>
		/// <param name="mailFilter">Filter instance.</param>
		public void SetFilter(IMailFilter? mailFilter) => Filter = mailFilter;

		/// <summary>
		/// Sets the TLS certificate of the server.
		/// </summary>
		/// <param name="certificate">Certificate used by the server</param>
		// ReSharper disable once InconsistentNaming
		public void SetTLSCertificate(X509Certificate certificate) => Certificate = certificate;

		internal Task DeliverMessage(MailTransaction transaction) => MailDeliveryInterface.EmailReceived(transaction);

		/// <summary>
		/// Adds a new listener to the server.
		/// </summary>
		/// <param name="ipAddress">Listening IP address</param>
		/// <param name="port">Listening port</param>
		/// <param name="tls">Whether listener always uses TLS</param>
		/// <param name="dualMode">Whether socket should use DualMode (listen on both IPv4 and IPv6 address). Works only if ipAddress is set to IPAddress.IPv6Any.</param>
		public void AddListener(IPAddress ipAddress, ushort port, bool tls, bool dualMode = false)
		{
			var l = new Listener(ipAddress, port, this, tls, dualMode);
			_listeners.Add(l);

			if (_started)
				l.Start();
		}

		/// <summary>
		/// <see cref="SMTPServer"/> finalizer
		/// </summary>
		~SMTPServer() => Dispose();
	}
}