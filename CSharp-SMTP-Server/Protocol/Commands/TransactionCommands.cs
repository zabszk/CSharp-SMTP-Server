using System;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Networking;

namespace CSharp_SMTP_Server.Protocol
{
	internal class TransactionCommands
	{
		internal static void ProcessCommand(ClientProcessor processor, string command, string data)
		{
			switch (command)
			{
				case "RSET":
					processor.Transaction = null;
					processor.WriteCode(250);
					break;

				case "MAIL FROM":
					{
						var address = ProcessAddress(data);
						if (address == null) processor.WriteCode(501);
						else
						{
							processor.Transaction = new MailTransaction()
							{
								From = address
							};
							processor.WriteCode(250);
						}
					}
					break;
					
				case "RCPT TO":
					{
						if (processor.Transaction == null)
						{
							processor.WriteCode(503);
							return;
						}

						var address = ProcessAddress(data);
						if (address == null) processor.WriteCode(501);
						else
						{
							if (!processor.Server.MailDeliveryInterface.UserExists(address))
							{
								processor.WriteCode(550);
								return;
							}

							processor.Transaction.To.Add(address);
							processor.WriteCode(250);
						}
					}
					break;

				case "DATA":
					if (processor.Transaction == null || processor.Transaction.To.Count == 0)
					{
						processor.WriteCode(503);
						return;
					}
					processor.CaptureData = 1;
					break;
			}
		}

		internal static void ProcessData(ClientProcessor processor, string data)
		{
			if (data == ".")
			{
				processor.CaptureData = 0;
				processor.Transaction.Body = processor.DataBuilder.ToString();
				if (!string.IsNullOrEmpty(processor.Username)) processor.Transaction.AuthenticatedUser = processor.Username;

				Task.Run(() => processor.Server.DeliverMessage(processor.Transaction));
				processor.Transaction = null;

				processor.WriteCode(250);
				return;
			}

			processor.DataBuilder.AppendLine(data);
		}

		private static string ProcessAddress(string data)
		{
			if (!data.Contains("<") || !data.Contains(">")) return null;

			var address = data.Substring(data.IndexOf("<", StringComparison.Ordinal) + 1);
			address = address.Substring(0, data.IndexOf(">", StringComparison.Ordinal));

			return string.IsNullOrWhiteSpace(address) ? null : address;
		}
	}
}
