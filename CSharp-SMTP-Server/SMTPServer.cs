using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	/// <summary>
	/// Instance of the SMTP server.
	/// </summary>
	public class SMTPServer : IDisposable
	{
		/// <summary>
		/// Server options.
		/// </summary>
		public ServerOptions Options;

		internal IMailDelivery MailDeliveryInterface { get; private set; }

		internal IAuthLogin AuthLogin { get; private set; }
		internal IMailFilter Filter { get; private set; }

		internal ILogger LoggerInterface { get; private set; }

		internal X509Certificate Certificate { get; private set; }

		internal List<Listener> Listeners { get; private set; }

        /// <summary>
        /// Initializes the instance of SMTP server without TLS certificate.
        /// </summary>
        /// <param name="parameters">Listening parameters</param>
        /// <param name="options">Server options</param>
        /// <param name="deliveryInterface">Interface used for email delivery.</param>
        /// <param name="loggerInterface">Interface used for logging server errors.</param>
        public SMTPServer(IEnumerable<ListeningParameters> parameters, ServerOptions options, IMailDelivery deliveryInterface, ILogger loggerInterface) :
			this(parameters, options, deliveryInterface, loggerInterface, null){}

		/// <summary>
		/// Initializes the instance of SMTP server with TLS certificate.
		/// </summary>
		/// <param name="parameters">Listening parameters</param>
		/// <param name="options">Server options</param>
		/// <param name="deliveryInterface">Interface used for email delivery.</param>
		/// <param name="loggerInterface">Interface used for logging server errors.</param>
		/// <param name="certificate">TLS certificate of the server.</param>
		public SMTPServer(IEnumerable<ListeningParameters> parameters, ServerOptions options, IMailDelivery deliveryInterface, ILogger loggerInterface,
			X509Certificate certificate)
		{
			if (SMTPCodes.Codes == null) SMTPCodes.Init();

			Options = options;
			MailDeliveryInterface = deliveryInterface;
			LoggerInterface = loggerInterface;
			Certificate = certificate;

			Listeners = new List<Listener>();

			foreach (var parameter in parameters)
			{
				foreach (var port in parameter.RegularPorts)
					Listeners.Add(new Listener(parameter.IpAddress, port, this, false));

				foreach (var port in parameter.TlsPorts)
					Listeners.Add(new Listener(parameter.IpAddress, port, this, true));
			}
		}

		/// <summary>
		/// Starts the server.
		/// </summary>
		public void Start() => Listeners.ForEach(listener => listener.Start());

		/// <summary>
		/// Stops and disposes the server.
		/// </summary>
		public void Dispose()
		{
			foreach (var listener in Listeners)
				listener?.Dispose();

			Certificate?.Dispose();
		}

		/// <summary>
		/// Sets the interface used for authentication. Enables authentication if not null.
		/// </summary>
		/// <param name="authInterface"></param>
		public void SetAuthLogin(IAuthLogin authInterface) => AuthLogin = authInterface;

        /// <summary>
        /// Sets the email filter.
        /// </summary>
        /// <param name="mailFilter">Filter instance.</param>
        public void SetFilter(IMailFilter mailFilter) => Filter = mailFilter;

        /// <summary>
        /// Sets the TLS certificate of the server.
        /// </summary>
        /// <param name="certificate">Certificate used by the server</param>
        public void SetTLSCertificate(X509Certificate certificate) => Certificate = certificate;

		internal void DeliverMessage(MailTransaction transaction) => MailDeliveryInterface.EmailReceived(transaction);
	}
}
