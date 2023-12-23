using System;
using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol.Responses;
using CSharp_SMTP_Server.Protocol;

namespace SampleApp;

internal class FilterInterface : IMailFilter
{
	//Allow all connections
	public Task<SmtpResult> IsConnectionAllowed(EndPoint ep) => Task.FromResult(new SmtpResult(SmtpResultType.Success));

	//Let's block .invalid TLD
	public Task<SmtpResult> IsAllowedSender(string source, EndPoint ep, string username) => Task.FromResult(source.TrimEnd().EndsWith(".invalid")
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new
			SmtpResult(SmtpResultType.Success));

	//Let's reject Softfail as well
	public Task<SmtpResult> IsAllowedSenderSpfVerified(string source, EndPoint ep, string username, ValidationResult validationResult) => Task.FromResult(validationResult == ValidationResult.Softfail
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
	public Task<SmtpResult> CanProcessTransaction(MailTransaction transaction) => Task.FromResult(transaction.GetMessageBody() != null && transaction.GetMessageBody()!.Contains("spam", StringComparison.OrdinalIgnoreCase)
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success));
}