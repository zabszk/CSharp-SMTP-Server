using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol.Commands
{
	internal class AuthenticationCommands
	{
		internal static void ProcessCommand(ClientProcessor processor, string data)
		{
			if (processor.Server.AuthLogin == null)
			{
				processor.WriteCode(502, "5.5.1");
				return;
			}

			if (processor.Server.Options.RequireEncryptionForAuth && !processor.Secure)
			{
				processor.WriteCode(538, "5.7.11");
				return;
			}

			var args = data.Contains(" ") ? data.Split(' ') : new[] {data};

			switch (args[0].ToUpper())
			{
				case "LOGIN":
					processor.CaptureData = 2;
					processor.WriteText("334 VXNlcm5hbWU6");
					break;

				case "PLAIN":
					if (args.Length == 1)
					{
						processor.CaptureData = 4;
						processor.WriteText("334");
					}
					else
					{
						processor.Username = AuthPlain(processor, args[1]);
						if (processor.Username == null)
							processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");
						else processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
					}
					break;

				default:
					processor.WriteCode(501, "5.7.4", "Unrecognized Authentication Method");
					break;
			}
		}

		internal static void ProcessData(ClientProcessor processor, string data)
		{
			switch (processor.CaptureData)
			{
				case 2:
					processor.TempUsername = Misc.Base64.Base64Decode(data);
					processor.CaptureData = 3;
					processor.WriteText("334 UGFzc3dvcmQ6");
					break;

				case 3:
					processor.CaptureData = 0;

					if (processor.Server.AuthLogin == null)
					{
						processor.WriteCode(454, "4.7.0", "Temporary authentication failure");
						return;
					}

					var decode = Misc.Base64.Base64Decode(data);
					if (processor.TempUsername != null && decode != null && processor.Server.AuthLogin.AuthLogin(processor.TempUsername, decode, processor.RemoteEndPoint, processor.Secure))
					{
						processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
						processor.Username = processor.TempUsername;
					}
					else
						processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");

					processor.TempUsername = null;
					break;

				case 4:
					processor.CaptureData = 0;

					processor.Username = AuthPlain(processor, data);
					if (processor.Username == null)
						processor.WriteCode(535, "5.7.8", "Authentication credentials invalid");
					else processor.WriteCode(235, "2.7.0", "Authentication Succeeded");
					break;
			}
		}

		private static string AuthPlain(ClientProcessor processor, string input)
		{
			var auth = Misc.Base64.Base64Decode(input);
			if (auth == null || !auth.Contains("\0")) return null;
			var split = auth.Split('\0');
			if (split.Length != 3) return null;
			return processor.Server.AuthLogin.AuthPlain(split[0], split[1], split[2], processor.RemoteEndPoint,
				processor.Secure) ? split[1] : null;
		}
	}
}
