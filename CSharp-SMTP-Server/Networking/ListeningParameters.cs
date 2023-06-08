using System.Net;

namespace CSharp_SMTP_Server.Networking
{
	/// <summary>
	/// Parameters of the listener.
	/// </summary>
	public class ListeningParameters
	{
		/// <summary>
		/// Class constructor
		/// </summary>
		/// <param name="ipAddress">Binding IP address</param>
		/// <param name="regularPorts">Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.</param>
		/// <param name="tlsPorts">Port numbers that always use TLS</param>
		public ListeningParameters(IPAddress ipAddress, ushort[]? regularPorts, ushort[]? tlsPorts)
		{
			IpAddress = ipAddress;
			RegularPorts = regularPorts;
			TlsPorts = tlsPorts;
		}

		/// <summary>
		/// Class constructor
		/// </summary>
		/// <param name="ipAddress">Binding IP address</param>
		/// <param name="regularPorts">Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.</param>
		/// <param name="tlsPorts">Port numbers that always use TLS</param>
		public ListeningParameters(string ipAddress, ushort[]? regularPorts, ushort[]? tlsPorts) : this(IPAddress.Parse(ipAddress), regularPorts, tlsPorts) { }

		/// <summary>
		/// Binding IP address
		/// </summary>
		public readonly IPAddress IpAddress;

		/// <summary>
		/// Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.
		/// </summary>
		public readonly ushort[]? RegularPorts;

		/// <summary>
		/// Port numbers that always use TLS
		/// </summary>
		public readonly ushort[]? TlsPorts;
	}
}