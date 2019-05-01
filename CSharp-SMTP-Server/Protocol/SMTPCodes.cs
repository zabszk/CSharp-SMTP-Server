using System.Collections.Generic;
using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol
{
	internal class SMTPCodes
	{
		internal static Dictionary<ushort, string> Codes;

		internal static void Init()
		{
			Codes = new Dictionary<ushort, string>
			{
				{214, "There is no help for you"},
				{221, "Service closing transmission channel"},
				{250, "OK"},
				{252, "Cannot VRFY user, but we will try to deliver the message anyway"},
				{354, "Start mail input; end with <CRLF>.<CRLF>"},
				{500, "Syntax error, command unrecognized"},
				{501, "Syntax error in parameters or arguments"},
				{502, "Unrecognized command"},
				{503, "Bad sequence of commands"},
				{538, "Encryption required for requested authentication mechanism"},
				{550, "Requested action not taken: mailbox unavailable"}
			};
		}

		internal static void SendCode(ClientProcessor proc, ushort code) => proc.WriteText($"{code} {Codes[code]}");

		internal static void SendCode(ClientProcessor proc, ushort code, string enhanced) =>
			proc.WriteText($"{code} {enhanced}  {Codes[code]}");

		internal static void SendCode(ClientProcessor proc, ushort code, string enhanced, string text) =>
			proc.WriteText($"{code} {enhanced}  {text}");
	}
}
