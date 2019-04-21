using System;
using System.Collections.Specialized;
using System.Text;
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
					processor.WriteCode(250, "2.1.5", "Flushed");
					break;

				case "MAIL FROM":
					{
						var address = ProcessAddress(data);
						if (address == null) processor.WriteCode(501, "5.5.2");
						else
						{
							processor.Transaction = new MailTransaction()
							{
								From = address,
								RemoteEndPoint = processor.RemoteEndPoint
							};
							processor.WriteCode(250, "2.0.0");
						}
					}
					break;
					
				case "RCPT TO":
					{
						if (processor.Transaction == null)
						{
							processor.WriteCode(503, "5.5.1", "MAIL FROM first.");
							return;
						}

						var address = ProcessAddress(data);
						if (address == null) processor.WriteCode(501);
						else
						{
							if (!processor.Server.MailDeliveryInterface.UserExists(address))
							{
								processor.WriteCode(550, "5.1.1");
								return;
							}

							processor.Transaction.To.Add(address);
							processor.WriteCode(250, "2.2.0");
						}
					}
					break;

				case "DATA":
					if (processor.Transaction == null || processor.Transaction.To.Count == 0)
					{
						processor.WriteCode(503, "5.5.1", "RCPT TO first.");
						return;
					}
					processor.DataBuilder = new StringBuilder();
					processor.CaptureData = 1;
					processor.WriteCode(354);
					break;
			}
		}

		internal static void ProcessData(ClientProcessor processor, string data)
		{
			data = data.Replace("\r", "");
			var dta = data.Split('\n');
			foreach (var dt in dta)
			{
				if (dt == ".")
				{
					processor.CaptureData = 0;
					processor.Transaction.Body = processor.DataBuilder.ToString();
					if (!string.IsNullOrEmpty(processor.Username)) processor.Transaction.AuthenticatedUser = processor.Username;

					var delivery = (MailTransaction)processor.Transaction.Clone();
					Task.Run(() => processor.Server.DeliverMessage(delivery));

					processor.Transaction = null;

					processor.WriteCode(250, "2.3.0");
					return;
				}

				processor.DataBuilder.AppendLine(dt);
			}
		}

		private static string ProcessAddress(string data)
		{
			if (!data.Contains("<") || !data.Contains(">")) return null;

			var address = data.Substring(data.IndexOf("<", StringComparison.Ordinal) + 1);
			address = address.Substring(0, address.IndexOf(">", StringComparison.Ordinal));

			return string.IsNullOrWhiteSpace(address) ? null : address;
		}
	}
}
