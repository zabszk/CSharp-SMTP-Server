using System;
using System.Text;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Config;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol.DKIM;
using CSharp_SMTP_Server.Protocol.DMARC;
using CSharp_SMTP_Server.Protocol.Responses;
using CSharp_SMTP_Server.Protocol.SPF;
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
						var address = AddressSyntax.ParsePath(data, processor.Server.Options.EmailAddressMaximumLength, processor.Server.Options.InternetDomainNameMaximumLength, true, out var domain);
						if (address == null) await processor.WriteCode(501, "5.5.2");
						else
						{
							// Null reverse-path (bounces) - RFC 7208, section 2.4: SPF checks the HELO/EHLO domain instead
							if (address.Length == 0)
								domain = AddressSyntax.IsValidDomain(processor.EhloDomain) ? processor.EhloDomain : null;

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

								if (processor.Server.Options.MailAuthenticationOptions.SpfOptions.AuthenticateEhloAddress && ehloSpfValidation == ValidationResult.CheckDisabled && AddressSyntax.IsValidDomain(processor.EhloDomain))
								{
									if (processor.SpfResultsCache!.TryGetValue(processor.EhloDomain, out spfRes))
										ehloSpfValidation = spfRes;
									else
									{
										ehloSpfValidation = await SpfValidator.CheckHost(processor.RemoteEndPoint!.Address, processor.EhloDomain);
										processor.SpfResultsCache.Add(processor.EhloDomain, ehloSpfValidation);
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

								if (domain == null)
									spfValidation = ValidationResult.None; // Null reverse-path without a valid HELO/EHLO domain
								else if (processor.SpfResultsCache!.TryGetValue(domain, out spfRes))
									spfValidation = spfRes;
								else
								{
									spfValidation = await SpfValidator.CheckHost(processor.RemoteEndPoint!.Address, domain);
									processor.SpfResultsCache.Add(domain, spfValidation);
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

							processor.Transaction = new MailTransaction(processor.EhloDomain, address, domain ?? string.Empty, spfValidation, ehloSpfValidation)
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

						var address = AddressSyntax.ParsePath(data, processor.Server.Options.EmailAddressMaximumLength, processor.Server.Options.InternetDomainNameMaximumLength, false, out _);
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
					processor.DataContainsBareCr = false;
					processor.CaptureData = 1;
					await processor.WriteCode(354);
					break;
			}
		}

		internal static async Task ProcessData(ClientProcessor processor, string line, bool endOfData)
		{
			if (!endOfData)
			{
				// RFC 5321, section 2.3.8: CR and LF must only be sent together as CRLF
				if (line.Contains('\r'))
					processor.DataContainsBareCr = true;

				var text = line.Length > 1 && line[0] == '.' && line[1] == '.' ? line[1..] : line;

				processor.Counter += (ulong)text.Length;
				if (processor.Server.Options.MessageCharactersLimit == 0 ||
				    processor.Server.Options.MessageCharactersLimit >= processor.Counter)
				{
					processor.DataBuilder!.AppendLine(text);
				}

				return;
			}

			processor.CaptureData = 0;

			var transaction = processor.Transaction!;
			var body = processor.DataBuilder!;
			var bareCr = processor.DataContainsBareCr;

			// The transaction is finished regardless of the outcome (accepted, rejected or an exception).
			// If it was left in place, another DATA command could reuse it, and the cached parsed message
			// of the previous DATA would be validated instead of the new message.
			processor.Transaction = null;
			processor.DataBuilder = null;
			processor.DataContainsBareCr = false;

			try
			{
				await FinishTransaction(processor, transaction, body, bareCr);
			}
			catch (Exception e)
			{
				processor.Server.LoggerInterface?.LogError("[Transaction processing] Exception: " + e.GetType().FullName + ", " + e.StackTrace + ", " + e.Message);
				await processor.WriteCode(451, "4.3.0", "Temporary server error, please try again later");
			}
		}

		private static async Task FinishTransaction(ClientProcessor processor, MailTransaction transaction, StringBuilder body, bool bareCr)
		{
			if (processor.Server.Options.MessageCharactersLimit != 0 &&
			    processor.Server.Options.MessageCharactersLimit < processor.Counter)
			{
				await processor.WriteCode(552, "5.4.3", "Message size exceeds the administrative limit.");
				return;
			}

			if (bareCr)
			{
				await processor.WriteCode(550, "5.6.0", "Message contains bare CR characters, message rejected");
				return;
			}

			// RFC 8601, section 5: Authentication-Results headers claiming to come from this server must be removed
			transaction.RawBody = RemoveOwnAuthenticationResults(body.ToString(), processor.Server.Options.ServerName);

			string received = string.Empty;

			if (!string.IsNullOrEmpty(processor.Username)) transaction.AuthenticatedUser = processor.Username;
			else if (processor.RemoteEndPoint == null) received = "from (unknown) ";
			else
			{
				var address = processor.RemoteEndPoint.Address;
				if (address.IsIPv4MappedToIPv6)
					address = address.MapToIPv4();

				received = transaction.EhloSPFValidationResult == ValidationResult.Pass && AddressSyntax.IsValidDomain(transaction.EhloDomain) ? $"from {transaction.EhloDomain} ({address}) " : $"from {address} ";
			}

			received += Invariant($"by {processor.Server.Options.ServerName} with SMTP; {DateTime.UtcNow:ddd, dd MMM yyyy HH:mm:ss} +0000 (UTC)");

			transaction.AddHeader("Received", received);

			if (transaction.SPFValidationResult != ValidationResult.UserAuthenticated && transaction.SPFValidationResult != ValidationResult.CheckDisabled)
			{
				// For the null reverse-path, the checked identity is the HELO/EHLO domain
				var spfIdentity = transaction.FromDomain.Length == 0 ? string.Empty
					: transaction.From.Length == 0 ? $" smtp.helo={transaction.FromDomain}"
					: $" smtp.mailfrom={transaction.FromDomain}";

				transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; spf={transaction.SPFValidationResult.ToString().ToLowerInvariant()}{spfIdentity}");
			}

			if (processor.Server.Options.MailAuthenticationOptions.DkimOptions.ValidateDkim)
			{
				if (processor.Username != null)
					transaction.DKIMValidationResult = new DkimValidator.DkimValidationResult(ValidationResult.UserAuthenticated);
				else
				{
					var dkimValidation = await processor.Server.DkimValidator!.ValidateTransaction(transaction);
					transaction.DKIMValidationResult = dkimValidation;

					string sigStatus = string.Empty;

					if (dkimValidation is {ValidationResult: ValidationResult.Pass or ValidationResult.Fail, RsaKeySize: > 0})
						sigStatus = $" ({dkimValidation.RsaKeySize}-bit key)";

					// Domain and selector come from the message, so they are only included if they can't alter the header structure
					var headerD = AddressSyntax.IsSafeAuthResultsValue(dkimValidation.Domain) ? $" header.d={dkimValidation.Domain}" : string.Empty;
					var headerS = AddressSyntax.IsSafeAuthResultsValue(dkimValidation.Selector) ? $" header.s={dkimValidation.Selector}" : string.Empty;

					transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; dkim={dkimValidation.ValidationResult.ToString().ToLowerInvariant()}{sigStatus}{headerD}{headerS}{dkimValidation.SignatureAlgorithmHeader}");
				}
			}

			if (transaction.DKIMValidationResult.ValidationResult != ValidationResult.Pass && transaction.DKIMValidationResult.ValidationResult != ValidationResult.UserAuthenticated)
			{
				switch (transaction.SPFValidationResult)
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
				if (transaction.ParsedMessage.From.Count > 1)
				{
					await processor.WriteCode(554, "5.7.1", "Message must not contain more than one From header, message rejected");
					return;
				}

				if (processor.Username != null)
					transaction.DMARCValidationResult = ValidationResult.UserAuthenticated;
				else
				{
					var dmarcValidation = await processor.Server.DmarcValidator!.ValidateTransaction(transaction);
					transaction.DMARCValidationResult = dmarcValidation;

					switch (dmarcValidation)
					{
						case ValidationResult.Fail when processor.Server.Options.MailAuthenticationOptions.DmarcOptions.RejectDmarcReject:
							await processor.WriteCode(554, "5.7.23", "Delivery not authorized by DMARC (Action: Reject), message rejected");
							return;

						case ValidationResult.Softfail when processor.Server.Options.MailAuthenticationOptions.DmarcOptions.RejectDmarcQuarantine:
							await processor.WriteCode(554, "5.7.23", "Delivery not authorized by DMARC (Action: Quarantine), message rejected");
							return;
					}

					// The From domain comes from the message, so it's only included if it can't alter the header structure
					var fromDomain = DmarcValidator.GetFromDomain(transaction.GetFrom);
					transaction.AddHeader("Authentication-Results", $"{processor.Server.Options.ServerName}; dmarc={dmarcValidation.ToString().ToLowerInvariant()} header.from={(AddressSyntax.IsSafeAuthResultsValue(fromDomain) ? fromDomain : "(none)")}");
				}
			}
			else transaction.DMARCValidationResult = ValidationResult.CheckDisabled;

			if (processor.Server.Filter != null)
			{
				var filterResult = await processor.Server.Filter.CanProcessTransaction(transaction);

				if (filterResult.Type != SmtpResultType.Success)
				{
					await processor.WriteCode(554,
						filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
						string.IsNullOrWhiteSpace(filterResult.FailMessage)
							? "Delivery not authorized, message rejected"
							: filterResult.FailMessage);
					return;
				}
			}

			_ = processor.Server.DeliverMessage((MailTransaction)transaction.Clone());

			await processor.WriteCode(250, "2.3.0");
		}

		/// <summary>
		/// Removes "Authentication-Results" header fields which claim to be added by this server (RFC 8601, section 5),
		/// so a sender can't forge authentication results attributed to this server.
		/// </summary>
		/// <param name="message">Raw message</param>
		/// <param name="authServId">Authentication service identifier of this server</param>
		/// <returns>Message without such header fields</returns>
		internal static string RemoveOwnAuthenticationResults(string message, string authServId)
		{
			if (message.IndexOf("Authentication-Results", StringComparison.OrdinalIgnoreCase) == -1)
				return message;

			var ownId = NormalizeAuthServId(authServId);
			var result = new StringBuilder(message.Length);
			var pos = 0;

			while (pos < message.Length)
			{
				// Empty line - end of the header section
				if (message[pos] == '\n' || (message[pos] == '\r' && pos + 1 < message.Length && message[pos + 1] == '\n'))
					break;

				// Find the end of the header field, including folded continuation lines
				var end = pos;
				do
				{
					var newLine = message.IndexOf('\n', end);
					end = newLine == -1 ? message.Length : newLine + 1;
				} while (end < message.Length && message[end] is ' ' or '\t');

				if (!IsAuthenticationResultsOf(message.AsSpan(pos, end - pos), ownId))
					result.Append(message, pos, end - pos);

				pos = end;
			}

			result.Append(message, pos, message.Length - pos);
			return result.ToString();
		}

		private static bool IsAuthenticationResultsOf(ReadOnlySpan<char> field, string normalizedAuthServId)
		{
			var colon = field.IndexOf(':');
			if (colon == -1 || !field[..colon].TrimEnd().Equals("Authentication-Results".AsSpan(), StringComparison.OrdinalIgnoreCase))
				return false;

			// The authserv-id is the first value, which may be quoted, surrounded by comments and followed by a version and ";".
			// Comparing with StartsWith (with whitespace removed) also catches "id 1;" (version) and comment/quoting tricks.
			return NormalizeAuthServId(field[(colon + 1)..]).StartsWith(normalizedAuthServId, StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Returns the value up to the first ";" outside of quotes and comments, with comments, quotes and whitespace removed.
		/// </summary>
		private static string NormalizeAuthServId(ReadOnlySpan<char> value)
		{
			var id = new StringBuilder();
			var commentDepth = 0;
			var quoted = false;

			for (var i = 0; i < value.Length; i++)
			{
				var c = value[i];

				if (c == '\\' && (quoted || commentDepth > 0))
				{
					i++;
					if (quoted && i < value.Length && !char.IsWhiteSpace(value[i]))
						id.Append(value[i]);
					continue;
				}

				if (quoted)
				{
					if (c == '"') quoted = false;
					else if (!char.IsWhiteSpace(c)) id.Append(c);
					continue;
				}

				if (commentDepth > 0)
				{
					if (c == '(') commentDepth++;
					else if (c == ')') commentDepth--;
					continue;
				}

				switch (c)
				{
					case '(':
						commentDepth++;
						break;

					case '"':
						quoted = true;
						break;

					case ';':
						return id.ToString();

					default:
						if (!char.IsWhiteSpace(c))
							id.Append(c);
						break;
				}
			}

			return id.ToString();
		}

		private static string NormalizeAuthServId(string value) => NormalizeAuthServId(value.AsSpan());
	}
}
