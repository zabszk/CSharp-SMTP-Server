using System.Collections.Generic;

namespace CSharp_SMTP_Server
{
	public class MailTransaction
	{
		public MailTransaction()
		{
			To = new List<string>();
			AuthenticatedUser = null;
		}

		public string From;
		public List<string> To;
		public string Body;

		public string AuthenticatedUser;
	}
}
