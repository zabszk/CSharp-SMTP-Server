using System;
using System.Net;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol.Responses;

namespace SampleApp
{
	class FilterInterface : IMailFilter
	{
		//Allow all connections
		public SmtpResult IsConnectionAllowed(EndPoint ep) => new SmtpResult(SmtpResultType.Success);

		//Let's block .invalid TLD. You can do here eg. SPF validation
		public SmtpResult IsAllowedSender(string source, EndPoint ep) => source.TrimEnd().EndsWith(".invalid")
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new
				SmtpResult(SmtpResultType.Success);

		//Let's block all emails to root at any domain
		public SmtpResult CanDeliver(string source, string destination, bool authenticated, string username,
			EndPoint ep) => destination.TrimStart().StartsWith("root@")
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new
				SmtpResult(SmtpResultType.Success);

		//Let's blacklist word "spam"
		public SmtpResult CanProcessTransaction(MailTransaction transaction) => transaction.Body.ToLower().Contains("spam")
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new SmtpResult(SmtpResultType.Success);
	}
}
