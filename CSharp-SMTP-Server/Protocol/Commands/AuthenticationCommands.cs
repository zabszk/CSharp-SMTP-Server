using System;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol.Commands
{
	internal static class AuthenticationCommands
	{
		internal static async Task ProcessCommand(ClientProcessor processor, string data)
		{
			if (processor.Server.AuthLogin == null)
			{
				await processor.WriteCode(502, "5.5.1");
				return;
			}

			if (processor.Server.Options.RequireEncryptionForAuth && !processor.Secure)
			{
				await processor.WriteCode(538, "5.7.11");
				return;
			}

			var args = data.Contains(' ', StringComparison.Ordinal) ? data.Split(' ') : new[] {data};

			switch (args[0].ToUpper())
			{
				case "LOGIN":
					processor.CaptureData = 2;
					await processor.WriteText("334 VXNlcm5hbWU6");
					break;

				case "PLAIN":
					if (args.Length == 1)
					{
						processor.CaptureData = 4;
						await processor.WriteText("334");
					}
					else
					{
						processor.Username = await AuthPlain(processor, args[1]);
						if (processor.Username == null)
							await processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");
						else await processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
					}
					break;

				default:
					await processor.WriteCode(501, "5.7.4", "Unrecognized Authentication Method");
					break;
			}
		}

		internal static async Task ProcessData(ClientProcessor processor, string data)
		{
			switch (processor.CaptureData)
			{
				case 2:
					processor.TempUsername = Misc.Base64.Base64Decode(data);
					processor.CaptureData = 3;
					await processor.WriteText("334 UGFzc3dvcmQ6");
					break;

				case 3:
					processor.CaptureData = 0;

					if (processor.Server.AuthLogin == null)
					{
						await processor.WriteCode(454, "4.7.0", "Temporary authentication failure");
						return;
					}

					var decode = Misc.Base64.Base64Decode(data);
					if (processor.TempUsername != null && decode != null && await processor.Server.AuthLogin.CheckAuthCredentials(processor.TempUsername, processor.TempUsername, decode, processor.RemoteEndPoint, processor.Secure))
					{
						await processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
						processor.Username = processor.TempUsername;
					}
					else
						await processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");

					processor.TempUsername = null;
					break;

				case 4:
					processor.CaptureData = 0;

					processor.Username = await AuthPlain(processor, data);
					if (processor.Username == null)
						await processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");
					else await processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
					break;
			}
		}

		private static async Task<string?> AuthPlain(ClientProcessor processor, string input)
		{
			var auth = Misc.Base64.Base64Decode(input);
			if (auth == null || !auth.Contains('\0', StringComparison.Ordinal)) return null;
			var split = auth.Split('\0');
			if (split.Length != 3) return null;
			return await processor.Server.AuthLogin!.CheckAuthCredentials(split[0], split[1], split[2], processor.RemoteEndPoint,
				processor.Secure)
				? split[1]
				: null;
		}
	}
}