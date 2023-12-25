using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Config;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol.DKIM;
using CSharp_SMTP_Server.Protocol.Responses;
using static System.FormattableString;

namespace CSharp_SMTP_Server.Protocol.Commands
{
	internal static class TransactionCommands
	{
		internal static async Task ProcessCommand(ClientProcessor processor, string command, string data)
		{
			switch (command)
			{
				case "RSET":
					processor.Transaction = null;
					await processor.WriteCode(250, "2.1.5", "Flushed");
					break;

				case "MAIL FROM":
					{
						var address = ProcessAddress(processor.Server.Options, data, out var domain);
						if (address == null) await processor.WriteCode(501, "5.5.2");
						else
						{
							if (processor.Server.Filter != null)
							{
								var result = await processor.Server.Filter.IsAllowedSender(address, processor.RemoteEndPoint, processor.Username);

								if (result.Type != SmtpResultType.Success)
								{
									await processor.WriteCode(554,
										result.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
										string.IsNullOrWhiteSpace(result.FailMessage)
											? "Delivery not authorized (MAIL FROM address not allowed), message rejected"
											: result.FailMessage);
									return;
								}
							}

							var spfValidation = ValidationResult.CheckDisabled;
							var ehloSpfValidation = processor.SpfValidationResult;

							if (processor.Username != null)
							{
								spfValidation = ValidationResult.UserAuthenticated;
								ehloSpfValidation = ValidationResult.UserAuthenticated;
							}
							else if (processor.Server.Options.MailAuthenticationOptions.SpfOptions.ValidateSpf)
							{
								ValidationResult spfRes;

								if (processor.Server.Options.MailAuthenticationOptions.SpfOptions.AuthenticateEhloAddress && ehloSpfValidation == ValidationResult.CheckDisabled && processor.Transaction!.EhloDomain != null)
								{
									if (processor.SpfResultsCache!.TryGetValue(processor.Transaction!.EhloDomain, out spfRes))
										ehloSpfValidation = spfRes;
									else
									{
										ehloSpfValidation = await processor.Server.SpfValidator!.CheckHost(processor.RemoteEndPoint!.Address, processor.Transaction!.EhloDomain);
										processor.SpfResultsCache.Add(processor.Transaction!.EhloDomain, ehloSpfValidation);
									}

									processor.SpfValidationResult = ehloSpfValidation;

									switch (ehloSpfValidation)
									{
										case ValidationResult.Fail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfFail:
											await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (EHLO/HELO Domain Result: Fail), message rejected");
											return;

										case ValidationResult.Softfail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfSoftfail:
											await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (EHLO/HELO Domain Result: Softfail), message rejected");
											return;
									}
								}

								if (processor.SpfResultsCache!.TryGetValue(domain!, out spfRes))
									spfValidation = spfRes;
								else
								{
									spfValidation = await processor.Server.SpfValidator!.CheckHost(processor.RemoteEndPoint!.Address, domain!);
									processor.SpfResultsCache.Add(domain!, spfValidation);
								}

								switch (spfValidation)
								{
									case ValidationResult.Fail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfFail && (!processor.Server.Options.MailAuthenticationOptions.SpfOptions.DkimPassOverridesSpfFail || !processor.Server.Options.MailAuthenticationOptions.DkimOptions.ValidateDkim):
										await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (Result: Fail), message rejected");
										return;

									case ValidationResult.Softfail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfSoftfail && (!processor.Server.Options.MailAuthenticationOptions.SpfOptions.DkimPassOverridesSpfSoftfail || !processor.Server.Options.MailAuthenticationOptions.DkimOptions.ValidateDkim):
										await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (Result: Softfail), message rejected");
										return;
								}
							}

							if (processor.Server.Filter != null)
							{
								var result = await processor.Server.Filter.IsAllowedSenderSpfVerified(address, processor.RemoteEndPoint, processor.Username, spfValidation);

								if (result.Type != SmtpResultType.Success)
								{
									await processor.WriteCode(554,
										result.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
										string.IsNullOrWhiteSpace(result.FailMessage)
											? "Delivery not authorized (MAIL FROM address not allowed), message rejected"
											: result.FailMessage);
									return;
								}
							}

							processor.Transaction = new MailTransaction(processor.EhloDomain, address, domain!, spfValidation, ehloSpfValidation)
							{
								RemoteEndPoint = processor.RemoteEndPoint,
								Encryption = processor.Encryption
							};
							await processor.WriteCode(250, "2.0.0");
						}
					}
					break;

				case "RCPT TO":
					{
						if (processor.Transaction == null)
						{
							await processor.WriteCode(503, "5.5.1", "MAIL FROM first.");
							return;
						}

						var address = ProcessAddress(processor.Server.Options, data, out _);
						if (address == null) await processor.WriteCode(501);
						else
						{
							if (processor.Server.Options.RecipientsLimit > 0 && processor.Server.Options.RecipientsLimit <= processor.Transaction.DeliverTo.Count)
							{
								await processor.WriteCode(550, "5.5.3", "Too many recipients");
								return;
							}

							if (processor.Server.Filter != null)
							{
								var filterResult = await processor.Server.Filter.CanDeliver(processor.Transaction.From, address, !string.IsNullOrEmpty(processor.Username), processor.Username, processor.RemoteEndPoint);

								if (filterResult.Type != SmtpResultType.Success)
								{
									await processor.WriteCode(550,
										filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
										string.IsNullOrWhiteSpace(filterResult.FailMessage)
											? "Delivery to this recipients is not allowed, message rejected"
											: filterResult.FailMessage);
									return;
								}
							}

							var result = await processor.Server.MailDeliveryInterface.DoesUserExist(address);

							switch (result)
							{
								case UserExistsCodes.BadDestinationMailboxAddress:
									await processor.WriteCode(550, "5.1.1", "Requested action not taken: Bad destination mailbox address");
									return;

								case UserExistsCodes.BadDestinationSystemAddress:
									await processor.WriteCode(550, "5.1.2", "Requested action not taken: Bad destination system address");
									return;

								case UserExistsCodes.DestinationMailboxAddressAmbiguous:
									await processor.WriteCode(550, "5.1.4", "Requested action not taken: Destination mailbox address ambiguous");
									return;

								case UserExistsCodes.DestinationAddressHasMovedAndNoForwardingAddress:
									await processor.WriteCode(550, "5.1.6", "Requested action not taken: Destination mailbox has moved, No forwarding address");
									return;

								case UserExistsCodes.BadSendersSystemAddress:
									await processor.WriteCode(550, "5.1.8", "Requested action not taken: Bad sender's mailbox address syntax");
									return;

								default:
									processor.Transaction.DeliverTo.Add(address);
									await processor.WriteCode(250, "2.1.5");
									break;
							}
						}
					}
					break;

				case "DATA":
					if (processor.Transaction == null || processor.Transaction.DeliverTo.Count == 0)
					{
						await processor.WriteCode(503, "5.5.1", "RCPT TO first.");
						return;
					}

					processor.DataBuilder = new StringBuilder();
					processor.Counter = 0;
					processor.CaptureData = 1;
					await processor.WriteCode(354);
					break;
			}
		}

		internal static async Task ProcessData(ClientProcessor processor, string data)
		{
			data = data.Replace("\r", "");
			var dta = data.Split('\n');
			foreach (var dt in dta)
			{
				if (dt == ".")
				{
					processor.CaptureData = 0;
					processor.Transaction!.RawBody = processor.DataBuilder!.ToString();

					if (processor.Server.Options.MessageCharactersLimit != 0 &&
					    processor.Server.Options.MessageCharactersLimit < processor.Counter)
					{
						processor.Transaction = null;
						await processor.WriteCode(552, "5.4.3", "Message size exceeds the administrative limit.");
						return;
					}

					string received = string.Empty;

					if (!string.IsNullOrEmpty(processor.Username)) processor.Transaction.AuthenticatedUser = processor.Username;
					else if (processor.RemoteEndPoint == null) received = "from (unknown) ";
					else
					{
						var address = processor.RemoteEndPoint.Address;
						if (address.IsIPv4MappedToIPv6)
							address = address.MapToIPv4();

						received = processor.Transaction.EhloSPFValidationResult == ValidationResult.Pass ? $"from {processor.Transaction.EhloDomain} ({address}) " : $"from {address} ";
					}

					received += Invariant($"by {processor.Server.Options.ServerName} with SMTP; {DateTime.UtcNow:ddd, dd MMM yyyy HH:mm:ss} +0000 (UTC)");

					processor.Transaction.AddHeader("Received", received);

					if (processor.Transaction.SPFValidationResult != ValidationResult.UserAuthenticated && processor.Transaction.SPFValidationResult != ValidationResult.CheckDisabled)
						processor.Transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; spf={processor.Transaction.SPFValidationResult.ToString().ToLowerInvariant()} smtp.mailfrom={processor.Transaction.FromDomain}");

					if (processor.Server.Options.MailAuthenticationOptions.DkimOptions.ValidateDkim)
					{
						if (processor.Username != null)
							processor.Transaction.DKIMValidationResult = new DkimValidator.DkimValidationResult(ValidationResult.UserAuthenticated);
						else
						{
							var dkimValidation = await processor.Server.DkimValidator!.ValidateTransaction(processor.Transaction);
							processor.Transaction.DKIMValidationResult = dkimValidation;

							string sigStatus = string.Empty;

							if (dkimValidation is {ValidationResult: ValidationResult.Pass or ValidationResult.Fail, RsaKeySize: > 0})
								sigStatus = $" ({dkimValidation.RsaKeySize}-bit key)";

							processor.Transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; dkim={dkimValidation.ToString().ToLowerInvariant()}{sigStatus} header.d={dkimValidation.Domain} header.s={dkimValidation.Selector}{dkimValidation.SignatureAlgorithmHeader}");
						}
					}

					if (processor.Transaction.DKIMValidationResult.ValidationResult != ValidationResult.Pass && processor.Transaction.DKIMValidationResult.ValidationResult != ValidationResult.UserAuthenticated)
					{
						switch (processor.Transaction.SPFValidationResult)
						{
							case ValidationResult.Fail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfFail:
								await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (Result: Fail), message rejected");
								return;

							case ValidationResult.Softfail when processor.Server.Options.MailAuthenticationOptions.SpfOptions.RejectSpfSoftfail:
								await processor.WriteCode(554, "5.7.23", "Delivery not authorized by SPF (Result: Softfail), message rejected");
								return;

							case ValidationResult.None when processor.Server.Options.MailAuthenticationOptions.RejectUnauthenticatedEmails:
							case ValidationResult.Neutral when processor.Server.Options.MailAuthenticationOptions.RejectUnauthenticatedEmails:
								await processor.WriteCode(554, "5.7.23", "Delivery not authorized - SPF or DKIM must be enabled and passed (SPF Result: None or Neutral), message rejected. Please contact your mail server administrator.");
								return;

							case ValidationResult.Temperror when processor.Server.Options.MailAuthenticationOptions.RejectUnauthenticatedEmails:
								await processor.WriteCode(554, "5.7.23", "Delivery not authorized - SPF or DKIM must be enabled and passed (SPF Result: Temperror), message rejected. Please contact your mail server administrator.");
								return;

							case ValidationResult.Permerror when processor.Server.Options.MailAuthenticationOptions.RejectUnauthenticatedEmails:
								await processor.WriteCode(554, "5.7.23", "Delivery not authorized - SPF or DKIM must be enabled and passed (SPF Result: Permerror), message rejected. Please contact your mail server administrator.");
								return;
						}
					}

					if (processor.Server.Options.MailAuthenticationOptions.DmarcOptions.ValidateDmarc)
					{
						if (processor.Transaction.ParsedMessage.From.Count > 1)
						{
							await processor.WriteCode(554, "5.7.1", "Message must not contain more than one From header, message rejected");
							return;
						}

						if (processor.Username != null)
							processor.Transaction.DMARCValidationResult = ValidationResult.UserAuthenticated;
						else
						{
							var dmarcValidation = await processor.Server.DmarcValidator!.ValidateTransaction(processor.Transaction);
							processor.Transaction.DMARCValidationResult = dmarcValidation;

							switch (dmarcValidation)
							{
								case ValidationResult.Fail when processor.Server.Options.MailAuthenticationOptions.DmarcOptions.RejectDmarcReject:
									await processor.WriteCode(554, "5.7.23", "Delivery not authorized by DMARC (Action: Reject), message rejected");
									return;

								case ValidationResult.Softfail when processor.Server.Options.MailAuthenticationOptions.DmarcOptions.RejectDmarcQuarantine:
									await processor.WriteCode(554, "5.7.23", "Delivery not authorized by DMARC (Action: Quarantine), message rejected");
									return;
							}

							ProcessAddress(processor.Server.Options, processor.Transaction.GetFrom, out var fromDomain);
							processor.Transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; dmarc={dmarcValidation.ToString().ToLowerInvariant()} header.from={fromDomain ?? "(none)"}");
						}
					}
					else processor.Transaction.DMARCValidationResult = ValidationResult.CheckDisabled;

					if (processor.Server.Filter != null)
					{
						var filterResult = await processor.Server.Filter.CanProcessTransaction(processor.Transaction);

						if (filterResult.Type != SmtpResultType.Success)
						{
							processor.Transaction = null;
							await processor.WriteCode(554,
								filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
								string.IsNullOrWhiteSpace(filterResult.FailMessage)
									? "Delivery not authorized, message rejected"
									: filterResult.FailMessage);
							return;
						}
					}

					var delivery = (MailTransaction)processor.Transaction.Clone();
					processor.Transaction = null;

					_ = processor.Server.DeliverMessage(delivery);

					await processor.WriteCode(250, "2.3.0");
					return;
				}

				processor.Counter += (ulong)dt.Length;
				if (processor.Server.Options.MessageCharactersLimit == 0 ||
				    processor.Server.Options.MessageCharactersLimit >= processor.Counter)
				{
					processor.DataBuilder!.AppendLine(dt);
				}
			}
		}

		internal static string? ProcessAddress(ServerOptions options, string? data, out string? domain)
		{
			domain = null;
			if (data == null)
				return null;

			if (!data.Contains('<', StringComparison.Ordinal) || !data.Contains('>', StringComparison.Ordinal)) return null;

			var address = data[(data.IndexOf("<", StringComparison.Ordinal) + 1)..];
			address = address[..address.IndexOf(">", StringComparison.Ordinal)];

			if (string.IsNullOrWhiteSpace(address))
				return null;

			var lastDotIndex = address.LastIndexOf('.');
			var atIndex = address.LastIndexOf('@');

			if (lastDotIndex == -1 || atIndex == -1 || lastDotIndex < atIndex)
				return null;

			if (address.Count(x => x == '@') != 1)
				return null;

			if (address.Length > options.EmailAddressMaximumLength)
				return null;

			domain = address[(atIndex + 1)..];

			if (domain.Length > options.InternetDomainNameMaximumLength)
			{
				domain = null;
				return null;
			}

			if (domain.Contains('.'))
				return address;

			domain = null;
			return null;
		}
	}
}