using System;
using System.Linq;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;
using CSharp_SMTP_Server.Protocol.Responses;

namespace SampleApp
{
	class DeliveryInterface : IMailDelivery
	{
		//Let's just print all emails
		public void EmailReceived(MailTransaction transaction) => Console.WriteLine(
			$"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo: {transaction.To.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");

		//We only own "@smtp.demo" and we don't want any emails to other domains
		public UserExistsCodes DoesUserExist(string emailAddress) => emailAddress.EndsWith("@smtp.demo")
			? UserExistsCodes.DestinationAddressValid
			: UserExistsCodes.BadDestinationSystemAddress;
	}
}
