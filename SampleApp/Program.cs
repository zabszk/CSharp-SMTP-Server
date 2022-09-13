using System;
using System.Net;
using CSharp_SMTP_Server;
using CSharp_SMTP_Server.Networking;

namespace SampleApp
{
	internal static class Program
	{
		private static void Main()
		{
			Console.WriteLine("Starting SMTP server on all IP addresses (both IPv4 and IPv6) on ports:\n- plain: 25, 587\n- TLS: 465");
			Console.WriteLine("Password for all accounts is \"123\".");

			var server = new SMTPServer(new[]
			{
				new ListeningParameters(IPAddress.Any, new ushort[]{25, 587}, new ushort[]{465}),
				new ListeningParameters(IPAddress.IPv6Any, new ushort[]{25, 587}, new ushort[]{465})
			}, new ServerOptions{ServerName = "Test SMTP Server", RequireEncryptionForAuth = false}, new DeliveryInterface(), new LoggerInterface());
			//with TLS:
			//}, new ServerOptions() { ServerName = "Test SMTP Server", RequireEncryptionForAuth = true}, new DeliveryInterface(), new LoggerInterface(), new X509Certificate2("PathToCertWithKey.pfx"));
			
			server.SetAuthLogin(new AuthenticationInterface());
			server.SetFilter(new FilterInterface());
			server.Start();

			Console.WriteLine("Server is running. Type \"exit\" to stop and exit.");

			while (true)
			{
				var read = Console.ReadLine();
				if (read != null && read.ToLower() == "exit") break;
			}

			Console.WriteLine("Stopping the server...");
			server.Dispose();
		}
	}
}
