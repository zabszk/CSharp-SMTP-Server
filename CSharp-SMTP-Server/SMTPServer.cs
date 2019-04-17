using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	public class SMTPServer : IDisposable
	{
		public ServerOptions Options;

		internal IMailDelivery MailDeliveryInterface { get; private set; }

		internal IAuthLogin AuthLogin { get; private set; }

		internal X509Certificate Certificate { get; private set; }

		internal List<Listener> Listeners { get; private set; }

		public SMTPServer(ListeningParameters[] parameters, ServerOptions options, IMailDelivery deliveryInterface) :
			this(parameters, options, deliveryInterface, null){}

		public SMTPServer(ListeningParameters[] parameters, ServerOptions options, IMailDelivery deliveryInterface,
			X509Certificate certificate)
		{
			if (SMTPCodes.Codes == null) SMTPCodes.Init();

			Options = options;
			MailDeliveryInterface = deliveryInterface;
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

		public void Start() => Listeners.ForEach(listener => listener.Start());

		public void Dispose()
		{
			foreach (var listener in Listeners)
				listener.Dispose();

			Certificate.Dispose();
		}

		public void SetAuthLogin(IAuthLogin authInterface) => AuthLogin = authInterface;

		public void SetTLSCertificate(X509Certificate certificate) => Certificate = certificate;

		internal void DeliverMessage(MailTransaction transaction) => MailDeliveryInterface.EmailReceived(transaction);
	}
}
