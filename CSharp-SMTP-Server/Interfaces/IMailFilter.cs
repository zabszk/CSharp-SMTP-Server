using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol.Responses;
using CSharp_SMTP_Server.Protocol.SPF;

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
		/// <returns>Whether connection is allowed</returns>
		Task<SmtpResult> IsConnectionAllowed(EndPoint? ep);

		/// <summary>
		/// Called when client sets \"From\" address.
		/// </summary>
		/// <param name="source">\"From\" value</param>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <param name="username">Username (if authenticated)</param>
		/// <returns>Whether the sender is authorized for this \"From\" value</returns>
		Task<SmtpResult> IsAllowedSender(string source, EndPoint? ep, string? username);

		/// <summary>
		/// Called when client sets is checked by SPF.
		/// This is NOT called when SPF validation equals \"Fail\".
		/// </summary>
		/// <param name="source">\"From\" value</param>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <param name="username">Username (if authenticated)</param>
		/// <param name="spfResult">SPF validation result</param>
		/// <returns>Whether the sender is authorized for this \"From\" value</returns>
		Task<SmtpResult> IsAllowedSenderSpfVerified(string source, EndPoint? ep, string? username, SpfResult spfResult);

		/// <summary>
		/// Called when client adds a recipient.
		/// </summary>
		/// <param name="source">\"From\" value</param>
		/// <param name="destination">Recipient being added</param>
		/// <param name="authenticated">User authentication status</param>
		/// <param name="username">Username (if authenticated)</param>
		/// <param name="ep">Remote endpoint of the connection</param>
		/// <returns>Whether email can be delivered</returns>
		Task<SmtpResult> CanDeliver(string source, string destination, bool authenticated, string? username, EndPoint? ep);

		/// <summary>
		/// Called when client finishes the mail transaction.
		/// </summary>
		/// <param name="transaction">Transaction being just finished.</param>
		/// <returns>Whether transaction can be processed</returns>
		Task<SmtpResult> CanProcessTransaction(MailTransaction transaction);
	}
}