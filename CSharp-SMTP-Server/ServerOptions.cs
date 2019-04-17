using System.Security.Authentication;

namespace CSharp_SMTP_Server
{
	public class ServerOptions
	{
		public string ServerName;
		public bool RequireEncryptionForAuth = true;
		public SslProtocols Protocols = SslProtocols.Tls12;
	}
}
