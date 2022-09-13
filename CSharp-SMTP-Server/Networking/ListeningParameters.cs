using System.Net;

namespace CSharp_SMTP_Server.Networking
{
	/// <summary>
	/// Parameters of the listener.
	/// </summary>
	public class ListeningParameters
	{
		public ListeningParameters(IPAddress ipAddress, ushort[]? regularPorts, ushort[]? tlsPorts)
		{
			IpAddress = ipAddress;
			RegularPorts = regularPorts;
			TlsPorts = tlsPorts;
		}
		
		/// <summary>
		/// Binding IP address.
		/// </summary>
		public readonly IPAddress IpAddress;
		
		/// <summary>
		/// Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.
		/// </summary>
		public readonly ushort[]? RegularPorts;
		
		/// <summary>
		/// Port numbers that always uses TLS
		/// </summary>
		public readonly ushort[]? TlsPorts;
	}
}
