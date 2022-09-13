using System.Collections.Generic;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol
{
	internal class SMTPCodes
	{
		private static readonly Dictionary<ushort, string> Codes;

		static SMTPCodes()
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

		internal static async Task SendCode(ClientProcessor proc, ushort code) => await proc.WriteText($"{code} {Codes[code]}");

		internal static async Task SendCode(ClientProcessor proc, ushort code, string enhanced) =>
			await proc.WriteText($"{code} {enhanced}  {Codes[code]}");

		internal static async Task SendCode(ClientProcessor proc, ushort code, string enhanced, string text) =>
			await proc.WriteText($"{code} {enhanced}  {text}");
	}
}
