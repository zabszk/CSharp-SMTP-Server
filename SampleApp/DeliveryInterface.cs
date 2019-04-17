using System;
using System.Linq;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp
{
	class DeliveryInterface : IMailDelivery
	{
		public void EmailReceived(MailTransaction transaction) => Console.WriteLine(
			$"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo: {transaction.To.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");

		public bool UserExists(string emailAddress) => true;
	}
}
