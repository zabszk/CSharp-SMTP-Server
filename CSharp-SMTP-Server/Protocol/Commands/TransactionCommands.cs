using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Misc;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol.Responses;

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
							if (processor.Server.Filter != null)
							{
								var result = processor.Server.Filter.IsAllowedSender(address, processor.RemoteEndPoint);

								if (result.Type != SmtpResultType.Success)
								{
									processor.WriteCode(554,
										result.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
										string.IsNullOrWhiteSpace(result.FailMessage)
											? "Delivery not authorized, message refused"
											: result.FailMessage);
									return;
								}
							}

							processor.Transaction = new MailTransaction()
							{
								From = address,
								RemoteEndPoint = processor.RemoteEndPoint,
								Encryption = processor.Encryption
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
                            if (processor.Server.Options.RecipientsLimit > 0 && processor.Server.Options.RecipientsLimit <= processor.Transaction.DeliverTo.Count)
                            {
                                processor.WriteCode(550, "5.5.3", "Too many recipients");
                                return;
                            }

							if (processor.Server.Filter != null)
							{
								var filterResult = processor.Server.Filter.CanDeliver(processor.Transaction.From,address, !string.IsNullOrEmpty(processor.Username), processor.Username, processor.RemoteEndPoint);

								if (filterResult.Type != SmtpResultType.Success)
								{
									processor.WriteCode(550,
										filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
										string.IsNullOrWhiteSpace(filterResult.FailMessage)
											? "Delivery not authorized, message refused"
											: filterResult.FailMessage);
									return;
								}
							}

							var result = processor.Server.MailDeliveryInterface.DoesUserExist(address);

							switch (result)
							{
								case UserExistsCodes.BadDestinationMailboxAddress:
									processor.WriteCode(550, "5.1.1", "Requested action not taken: Bad destination mailbox address");
									return;

								case UserExistsCodes.BadDestinationSystemAddress:
									processor.WriteCode(550, "5.1.2", "Requested action not taken: Bad destination system address");
									return;

								case UserExistsCodes.DestinationMailboxAddressAmbiguous:
									processor.WriteCode(550, "5.1.4", "Requested action not taken: Destination mailbox address ambiguous");
									return;

								case UserExistsCodes.DestinationAddressHasMovedAndNoForwardingAddress:
									processor.WriteCode(550, "5.1.6", "Requested action not taken: Destination mailbox has moved, No forwarding address");
									return;

								case UserExistsCodes.BadSendersSystemAddress:
									processor.WriteCode(550, "5.1.8", "Requested action not taken: Bad sender's mailbox address syntax");
									return;

								default:
									processor.Transaction.DeliverTo.Add(address);
									processor.WriteCode(250, "2.1.5");
									break;
							}	
						}
					}
					break;

				case "DATA":
					if (processor.Transaction == null || processor.Transaction.DeliverTo.Count == 0)
					{
						processor.WriteCode(503, "5.5.1", "RCPT TO first.");
						return;
					}

					processor.DataBuilder = new StringBuilder();
                    processor.Counter = 0;
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

                    if (processor.Server.Options.MessageCharactersLimit != 0 &&
                        processor.Server.Options.MessageCharactersLimit < processor.Counter)
                    {
                        processor.Transaction = null;
                        processor.WriteCode(552, "5.4.3", "Message size exceeds the administrative limit.");
                        return;
                    }

                    if (!string.IsNullOrEmpty(processor.Username)) processor.Transaction.AuthenticatedUser = processor.Username;
                    processor.Transaction.Headers = EmailParser.ParseHeaders(processor.Transaction.Body);

                    if (processor.Server.Filter != null)
					{
						var filterResult = processor.Server.Filter.CanProcessTransaction(processor.Transaction);

						if (filterResult.Type != SmtpResultType.Success)
						{
                            processor.Transaction = null;
                            processor.WriteCode(554,
								filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
								string.IsNullOrWhiteSpace(filterResult.FailMessage)
									? "Delivery not authorized, message refused"
									: filterResult.FailMessage);
							return;
						}
					}

                    var delivery = (MailTransaction)processor.Transaction.Clone();
                    processor.Transaction = null;

                    Task.Run(() => processor.Server.DeliverMessage(delivery));

					processor.WriteCode(250, "2.3.0");
					return;
				}

                processor.Counter += (ulong)dt.Length;
                if (processor.Server.Options.MessageCharactersLimit == 0 ||
                    processor.Server.Options.MessageCharactersLimit >= processor.Counter)
                {
                    processor.DataBuilder.AppendLine(dt);
                }
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
