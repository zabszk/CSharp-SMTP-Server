using System.Net;

namespace CSharp_SMTP_Server.Networking
{
	public class ListeningParameters
	{
		public IPAddress IpAddress;
		public ushort[] RegularPorts;
		public ushort[] TlsPorts;
	}
}
