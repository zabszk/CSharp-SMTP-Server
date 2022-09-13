using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol.Responses;

namespace CSharp_SMTP_Server.Interfaces
{
	/// <summary>
	/// Interface handling emails delivery.
	/// </summary>
	public interface IMailDelivery
	{
		/// <summary>
		/// Called when email transaction has been finished.
		/// </summary>
		/// <param name="transaction">Finished transaction.</param>
		Task EmailReceived(MailTransaction transaction);

		/// <summary>
		/// Called when new recipient is being added.
		/// </summary>
		/// <param name="emailAddress">Email address being added as recipient.</param>
		/// <returns>Is email address valid recipient or not.</returns>
		Task<UserExistsCodes> DoesUserExist(string emailAddress);
	}
}
