using CSharp_SMTP_Server.Protocol.Responses;

namespace CSharp_SMTP_Server.Interfaces
{
	public interface IMailDelivery
	{
		void EmailReceived(MailTransaction transaction);

		UserExistsCodes DoesUserExist(string emailAddress);
	}
}
