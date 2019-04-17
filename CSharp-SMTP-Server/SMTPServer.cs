using System.Security.Cryptography.X509Certificates;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	public class SMTPServer
	{
		public ServerOptions Options;
		internal IMailDelivery MailDeliveryInterface;
		internal IAuthLogin AuthLogin;
		internal X509Certificate Certificate;

		public void Init(IMailDelivery deliveryInterface)
		{
			if (SMTPCodes.Codes == null) SMTPCodes.Init();

			MailDeliveryInterface = deliveryInterface;
		}

		public void SetAuthLogin(IAuthLogin authInterface) => AuthLogin = authInterface;
		public void SetTLSCertificate(X509Certificate certificate) => Certificate = certificate;

		internal void DeliverMessage(MailTransaction transaction) => MailDeliveryInterface.EmailReceived(transaction);
	}
}
