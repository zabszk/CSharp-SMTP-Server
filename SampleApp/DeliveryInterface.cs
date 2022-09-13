using System;
using System.Linq;
using System.Threading.Tasks;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol.Responses;

namespace SampleApp
{
	class DeliveryInterface : IMailDelivery
	{
		//Let's just print all emails
		public Task EmailReceived(MailTransaction transaction)
		{
			Console.WriteLine(
				$"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo (Commands): {transaction.DeliverTo.Aggregate((current, item) => current + ", " + item)}\nTo (Headers): {transaction.To.Aggregate((current, item) => current + ", " + item)}\nCc: {transaction.Cc.Aggregate((current, item) => current + ", " + item)}\nBcc: {transaction.Bcc.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");
			return Task.CompletedTask;
		}

		//We only own "@smtp.demo" and we don't want any emails to other domains
		public Task<UserExistsCodes> DoesUserExist(string emailAddress) => Task.FromResult(emailAddress.EndsWith("@smtp.demo", StringComparison.OrdinalIgnoreCase)
			? UserExistsCodes.DestinationAddressValid
			: UserExistsCodes.BadDestinationSystemAddress);
	}
}
