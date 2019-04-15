using System;
using System.Collections.Generic;
using System.Text;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	public class SMTPServer
	{
		public ServerOptions Options;
		internal IMailDelivery MailDeliveryInterface;

		public void Init(IMailDelivery deliveryInterface)
		{
			if (SMTPCodes.Codes == null) SMTPCodes.Init();

			MailDeliveryInterface = deliveryInterface;
		}
	}
}
