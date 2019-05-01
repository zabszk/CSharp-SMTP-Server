using System.Net;

namespace CSharp_SMTP_Server.Networking
{
	/// <summary>
	/// Parameters of the listener.
	/// </summary>
	public class ListeningParameters
	{
		/// <summary>
		/// Binding IP address.
		/// </summary>
		public IPAddress IpAddress;
		/// <summary>
		/// Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.
		/// </summary>
		public ushort[] RegularPorts;
		/// <summary>
		/// Port numbers that always uses encryption
		/// </summary>
		public ushort[] TlsPorts;
	}
}
