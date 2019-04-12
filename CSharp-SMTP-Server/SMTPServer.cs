using System;
using System.Collections.Generic;
using System.Text;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	public class SMTPServer
	{
		public ServerOptions Options;

		public void Init()
		{
			if (SMTPCodes.Codes == null) SMTPCodes.Init();
		}
	}
}
