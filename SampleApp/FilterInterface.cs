using System;
using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol.Responses;

namespace SampleApp
{
	class FilterInterface : IMailFilter
	{
		//Allow all connections
		public Task<SmtpResult> IsConnectionAllowed(EndPoint ep) => Task.FromResult(new SmtpResult(SmtpResultType.Success));

		//Let's block .invalid TLD. You can do here eg. SPF validation
		public Task<SmtpResult> IsAllowedSender(string source, EndPoint ep) => Task.FromResult(source.TrimEnd().EndsWith(".invalid")
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new
				SmtpResult(SmtpResultType.Success));

		//Let's block all emails to root at any domain
		public Task<SmtpResult> CanDeliver(string source, string destination, bool authenticated, string username,
			EndPoint ep) => Task.FromResult(destination.TrimStart().StartsWith("root@", StringComparison.OrdinalIgnoreCase)
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new
				SmtpResult(SmtpResultType.Success));

		//Let's blacklist word "spam"
		public Task<SmtpResult> CanProcessTransaction(MailTransaction transaction) => Task.FromResult(transaction.RawBody != null && transaction.RawBody.ToLower().Contains("spam", StringComparison.OrdinalIgnoreCase)
			? new SmtpResult(SmtpResultType.PermanentFail)
			: new SmtpResult(SmtpResultType.Success));
	}
}
