using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol
{
	public class SMTPCodes
	{
		public static Dictionary<int, string> Codes;

		internal static void Init()
		{
			Codes.Add(250, "OK");

			Codes.Add(354, "Start mail input; end with <CRLF>.<CRLF>");

			Codes.Add(501, "Syntax error in parameters or arguments");
			Codes.Add(503, "Bad sequence of commands");
			Codes.Add(550, "Requested action not taken: mailbox unavailable");
		}

		internal static void SendCode(ClientProcessor proc, int code) => proc.WriteText($"{code} {Codes[code]}");
	}
}
