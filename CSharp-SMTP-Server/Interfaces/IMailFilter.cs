using System.Net;
using CSharp_SMTP_Server.Protocol.Responses;

namespace CSharp_SMTP_Server.Interfaces
{
	public interface IMailFilter
	{
		SmtpResult IsConnectionAllowed(EndPoint ep);

		SmtpResult IsAllowedSender(string source, EndPoint ep);

		SmtpResult CanDeliver(string source, string destination, bool authenticated, string username, EndPoint ep);

		SmtpResult CanProcessTransaction(MailTransaction transaction);
	}
}
