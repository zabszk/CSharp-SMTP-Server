namespace CSharp_SMTP_Server.Interfaces
{
	public interface IMailDelivery
	{
		void EmailReceived(MailTransaction transaction);

		bool UserExists(string emailAddress);
	}
}
