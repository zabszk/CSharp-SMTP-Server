using System;
using System.Collections.Generic;
using System.Net;
using CSharp_SMTP_Server.Networking;

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

		/// <summary>
		/// Username of authenticated users. Empty if user is not authenticated.
		/// </summary>
		public string AuthenticatedUser;

		public ConnectionEncryption Encryption;

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
