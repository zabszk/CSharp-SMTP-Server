using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol.Responses;

namespace CSharp_SMTP_Server.Interfaces
{
    /// <summary>
    /// Interface for handling emails filtering.
    /// </summary>
    public interface IMailFilter
	{
		/// <summary>
		/// Called when new connection has been established.
		/// </summary>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <returns></returns>
		Task<SmtpResult> IsConnectionAllowed(EndPoint? ep);

		/// <summary>
		/// Called when client sets \"From\" address.
		/// </summary>
		/// <param name="source">\"From\" value</param>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <returns></returns>
		Task<SmtpResult> IsAllowedSender(string source, EndPoint? ep);

		/// <summary>
		/// Called when client adds a recipient.
		/// </summary>
		/// <param name="source">\"From\" value</param>
		/// <param name="destination">Recipient being added</param>
		/// <param name="authenticated">User authentication status</param>
		/// <param name="username">Username (if authenticated)</param>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <returns></returns>
		Task<SmtpResult> CanDeliver(string source, string destination, bool authenticated, string? username, EndPoint? ep);

		/// <summary>
		/// Called when client finishes the mail transaction.
		/// </summary>
		/// <param name="transaction">Transaction being just finished.</param>
		/// <returns></returns>
		Task<SmtpResult> CanProcessTransaction(MailTransaction transaction);
	}
}
