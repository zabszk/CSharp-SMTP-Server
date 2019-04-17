using System;
using System.Collections.Generic;
using System.Net;

namespace CSharp_SMTP_Server
{
	public class MailTransaction : ICloneable
	{
		public MailTransaction()
		{
			To = new List<string>();
			AuthenticatedUser = null;
		}

		public string From;
		public List<string> To;
		public string Body;

		public EndPoint RemoteEndPoint;
		public string AuthenticatedUser;

		public object Clone()
		{
			return new MailTransaction()
			{
				AuthenticatedUser = AuthenticatedUser,
				Body = Body,
				From = From,
				RemoteEndPoint = RemoteEndPoint,
				To = To
			};
		}
	}
}
