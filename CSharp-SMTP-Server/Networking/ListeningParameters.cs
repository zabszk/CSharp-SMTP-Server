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
		/// <param name="dualMode">Whether socket should use DualMode (listen on both IPv4 and IPv6 address). Works only if ipAddress is set to IPAddress.IPv6Any.</param>
		// ReSharper disable once MemberCanBePrivate.Global
		public ListeningParameters(IPAddress ipAddress, ushort[]? regularPorts, ushort[]? tlsPorts, bool dualMode = false)
		{
			IpAddress = ipAddress;
			RegularPorts = regularPorts;
			TlsPorts = tlsPorts;
			DualMode = dualMode;
		}

		/// <summary>
		/// Class constructor
		/// </summary>
		/// <param name="ipAddress">Binding IP address</param>
		/// <param name="regularPorts">Port of non-encrypted ports. Client can use StartTLS on that ports, if certificate is provided.</param>
		/// <param name="tlsPorts">Port numbers that always use TLS</param>
		/// <param name="dualMode">Whether socket should use DualMode (listen on both IPv4 and IPv6 address). Works only if ipAddress is set to IPAddress.IPv6Any.</param>
		public ListeningParameters(string ipAddress, ushort[]? regularPorts, ushort[]? tlsPorts, bool dualMode = false) : this(IPAddress.Parse(ipAddress), regularPorts, tlsPorts, dualMode) { }

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

		/// <summary>
		/// Whether socket should use DualMode (listen on both IPv4 and IPv6 address).
		/// Works only if ipAddress is set to IPAddress.IPv6Any.
		/// </summary>
		public readonly bool DualMode;
	}
}