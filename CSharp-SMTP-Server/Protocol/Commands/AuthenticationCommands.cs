using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol.Commands
{
	internal class AuthenticationCommands
	{
		internal static void ProcessCommand(ClientProcessor processor, string data)
		{
			if (processor.Server.AuthLogin == null)
			{
				processor.WriteCode(502);
				return;
			}

			if (processor.Server.Options.RequireEncryptionForAuth && !processor.Secure)
			{
				processor.WriteText("538 5.7.11  Encryption required for requested authentication mechanism");
				return;
			}

			if (!data.Contains(" "))
			{
				processor.WriteCode(501);
				return;
			}

			var args = data.Split(' ');

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
						processor.WriteText(processor.Username == null
							? "535 5.7.8  Authentication credentials invalid"
							: "235 2.7.0  Authentication Succeeded");
					}
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
						processor.WriteText("454 4.7.0  Temporary authentication failure");
						return;
					}

					if (processor.Server.AuthLogin.AuthLogin(processor.TempUsername, Misc.Base64.Base64Decode(data), processor.RemoteEndPoint, processor.Secure))
					{
						processor.WriteText("235 2.7.0  Authentication Succeeded");
						processor.Username = processor.TempUsername;
					}
					else
						processor.WriteText("535 5.7.8  Authentication credentials invalid");

					processor.TempUsername = null;
					break;

				case 4:
					processor.CaptureData = 0;

					processor.Username = AuthPlain(processor, data);
					processor.WriteText(processor.Username == null
						? "535 5.7.8  Authentication credentials invalid"
						: "235 2.7.0  Authentication Succeeded");
					break;
			}
		}

		private static string AuthPlain(ClientProcessor processor, string input)
		{
			var auth = Misc.Base64.Base64Decode(input);
			if (!auth.Contains('\0')) return null;
			var split = auth.Split('\0');
			if (split.Length != 3) return null;
			return processor.Server.AuthLogin.AuthPlain(split[0], split[1], split[2], processor.RemoteEndPoint,
				processor.Secure) ? split[1] : null;
		}
	}
}
