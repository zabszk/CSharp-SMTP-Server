using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Data.Records;
using DnsClient.Enums;
using DnsClient.Logging;
// ReSharper disable MemberCanBePrivate.Global

namespace CSharp_SMTP_Server.Protocol.SPF;

/// <summary>
/// SPF validator
/// </summary>
public class SpfValidator
{
	private readonly DnsClient.DnsClient _dnsClient;

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="server">SMTP server which configuration should be used</param>
	public SpfValidator(SMTPServer server) : this(server.Options.DnsServerEndpoint, new DnsLogger(server)) { }

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsClient">DNS client used for SPF validation</param>
	public SpfValidator(DnsClient.DnsClient dnsClient) => _dnsClient = dnsClient;

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsServerEndpoint">DNS server endpoint</param>
	/// <param name="dnsClientOptions">DNS client options</param>
	public SpfValidator(EndPoint dnsServerEndpoint, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerEndpoint, dnsClientOptions)) { }

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsServerEndpoint">DNS server endpoint</param>
	/// <param name="errorLogging">DNS client error logging interface</param>
	public SpfValidator(EndPoint dnsServerEndpoint, IErrorLogging? errorLogging) : this(dnsServerEndpoint, new DnsClientOptions {ErrorLogging = errorLogging}) { }

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsServerAddress">DNS server IP address</param>
	/// <param name="dnsServerPort">DNS server port</param>
	/// <param name="dnsClientOptions">DNS client options</param>
	public SpfValidator(IPAddress dnsServerAddress, ushort dnsServerPort = 53, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerAddress, dnsServerPort, dnsClientOptions)) { }

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsServerAddress">DNS server IP address</param>
	/// <param name="dnsServerPort">DNS server port</param>
	/// <param name="dnsClientOptions">DNS client options</param>
	public SpfValidator(string dnsServerAddress, ushort dnsServerPort = 53, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerAddress, dnsServerPort, dnsClientOptions)) { }

	/// <summary>
	/// RFC 7208 (SPF) check_host() function
	/// Authenticates remote SMTP server.
	/// </summary>
	/// <param name="ipAddress">IP address of the remote SMTP server</param>
	/// <param name="domain">Email sender domain</param>
	/// <param name="requestsCounter">Requests counter value before a recursive call</param>
	/// <param name="ptrUsed">Indicates whether a PTR algorithm was used before a recursive call</param>
	/// <returns>SPF validation result</returns>
	public async Task<SpfResult> CheckHost(IPAddress ipAddress, string domain, uint requestsCounter = 0, bool ptrUsed = false)
	{
		var txtQuery = await _dnsClient.Query(domain, QType.TXT);

		if (txtQuery.ErrorCode != DnsErrorCode.NoError || txtQuery.Records == null)
			return SpfResult.Temperror;

		string? record = null;

		foreach (var r in txtQuery.Records)
		{
			if (r is not DnsRecord.TXTRecord t || !t.Text.StartsWith("v=spf1 ", StringComparison.Ordinal))
				continue;

			if (record != null)
				return SpfResult.Permerror;

			record = t.Text;
		}

		if (record == null)
			return SpfResult.None;

		record = record[7..].TrimEnd();
		var sp = record.Split(' ', StringSplitOptions.RemoveEmptyEntries);
		uint requestsMade = requestsCounter;
		bool ptrWasUsed = ptrUsed;

		foreach (var s in sp)
		{
			var qualifier = SpfResult.Pass;
			var mechanism = s;
			string? args = null;
			byte? cidr = null;

			switch (s[0])
			{
				case '+':
					mechanism = s[1..];
					break;

				case '-':
					qualifier = SpfResult.Fail;
					mechanism = s[1..];
					break;

				case '~':
					qualifier = SpfResult.Softfail;
					mechanism = s[1..];
					break;

				case '?':
					qualifier = SpfResult.Neutral;
					mechanism = s[1..];
					break;
			}

			if (mechanism == "")
				continue;

			if (mechanism.Contains('/'))
			{
				var index = mechanism.IndexOf('/');

				if (mechanism.Length > index && byte.TryParse(mechanism[(index + 1)..], out var cd))
					cidr = cd;

				mechanism = mechanism[..index];
			}

			if (mechanism.Contains(':'))
			{
				var index = mechanism.IndexOf(':');

				if (mechanism.Length > index)
					args = mechanism[(index + 1)..];

				mechanism = mechanism[..index];
			}
			else if (mechanism.Contains('='))
			{
				var index = mechanism.IndexOf('=');

				if (mechanism.Length > index)
					args = mechanism[(index + 1)..];

				mechanism = mechanism[..index];
			}

			if (mechanism == "")
				continue;

			switch (mechanism.ToLowerInvariant())
			{
				case "all":
					return qualifier;

				case "a" when ipAddress.AddressFamily == AddressFamily.InterNetwork:
				case "a" when ipAddress.AddressFamily == AddressFamily.InterNetworkV6:
					{
						if (requestsMade > 10)
							return ptrWasUsed ? SpfResult.Fail : SpfResult.Permerror;

						requestsMade++;

						var result = await CheckAddressMatch(ipAddress, domain, args, cidr, qualifier);
						if (result != SpfResult.None)
							return qualifier;
					}
					break;

				case "a":
					return SpfResult.Permerror;

				case "mx":
					{
						if (requestsMade > 10)
							return ptrWasUsed ? SpfResult.Fail : SpfResult.Permerror;

						requestsMade++;

						var mxQuery = await _dnsClient.Query(args ?? domain, QType.MX);

						if (mxQuery.ErrorCode != DnsErrorCode.NoError || mxQuery.Records == null)
							return SpfResult.Temperror;

						foreach (var q in mxQuery.Records)
						{
							if (q is not DnsRecord.MXRecord ar)
								continue;

							if (requestsMade > 10)
								return SpfResult.Permerror;

							requestsMade++;

							var result = await CheckAddressMatch(ipAddress, ar.MailExchange, null, cidr, qualifier);
							if (result != SpfResult.None)
								return qualifier;
						}
					}
					break;

				case "ptr":
					{
						if (requestsMade > 10)
							return ptrWasUsed ? SpfResult.Fail : SpfResult.Permerror;

						requestsMade++;

						var ptrQuery = await _dnsClient.QueryReverseDNS(ipAddress);

						if (ptrQuery.ErrorCode != DnsErrorCode.NoError || ptrQuery.Records == null)
							continue;

						foreach (var q in ptrQuery.Records)
						{
							if (q is not DnsRecord.PTRRecord ar)
								continue;

							if (!ar.DomainName.Equals(domain, StringComparison.OrdinalIgnoreCase) && !ar.DomainName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
								continue;

							if (requestsMade > 10)
								return SpfResult.Fail;

							requestsMade++;
							ptrWasUsed = true;

							if (await CheckAddressMatch(ipAddress, ar.DomainName, null, null, SpfResult.Pass) == SpfResult.Pass)
								return qualifier;
						}
					}
					break;

				case "ip4" when args != null && ipAddress.AddressFamily == AddressFamily.InterNetwork && IPAddress.TryParse(args, out var ipParsed):
					{
						if (cidr is null or > 32)
							cidr = 32;

						if (CheckCIDR(ipAddress, ipParsed, cidr.Value))
							return qualifier;
					}
					break;

				case "ip6" when args != null && ipAddress.AddressFamily == AddressFamily.InterNetworkV6 && IPAddress.TryParse(args, out var ipParsed):
					{
						if (cidr is null or > 128)
							cidr = 128;

						if (CheckCIDR(ipAddress, ipParsed, cidr.Value))
							return qualifier;
					}
					break;

				case "redirect" when args != null:
					{
						if (sp.Any(c => c.Equals("all", StringComparison.OrdinalIgnoreCase) || (c.Length == 4 && c.EndsWith("all", StringComparison.OrdinalIgnoreCase))))
							continue;

						if (requestsMade > 10)
							return SpfResult.Permerror;

						requestsMade++;

						var check = await CheckHost(ipAddress, args, requestsMade, ptrWasUsed);
						return check == SpfResult.None ? SpfResult.Permerror : check;
					}

				case "include" when args != null:
					{
						if (requestsMade > 10)
							return SpfResult.Permerror;

						requestsMade++;

						switch (await CheckHost(ipAddress, args, requestsMade, ptrWasUsed))
						{
							case SpfResult.Pass:
								return qualifier;

							case SpfResult.Temperror:
								return SpfResult.Temperror;

							case SpfResult.Permerror:
							case SpfResult.None:
								return SpfResult.Permerror;
						}
						break;
					}
			}
		}

		return SpfResult.Neutral;
	}

	private async Task<SpfResult> CheckAddressMatch(IPAddress ipAddress, string domain, string? args, int? cidr, SpfResult qualifier)
	{
		var aQuery = await _dnsClient.Query(args ?? domain, ipAddress.AddressFamily == AddressFamily.InterNetwork ? QType.A : QType.AAAA);

		if (aQuery.ErrorCode != DnsErrorCode.NoError || aQuery.Records == null)
			return SpfResult.Temperror;

		if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
		{
			if (cidr is null or > 32)
				cidr = 32;

			foreach (var q in aQuery.Records)
			{
				if (q is not DnsRecord.ARecord ar)
					continue;

				if (CheckCIDR(ar.Address, ipAddress, (byte)cidr))
					return qualifier;
			}
		}
		else
		{
			if (cidr is null or > 128)
				cidr = 128;

			foreach (var q in aQuery.Records)
			{
				if (q is not DnsRecord.AAAARecord ar)
					continue;

				if (CheckCIDR(ar.Address, ipAddress, (byte)cidr))
					return qualifier;
			}
		}

		return SpfResult.None;
	}

	/// <summary>
	/// Checks if two IP addresses belong to the same subnet
	/// </summary>
	/// <param name="a">First IP address</param>
	/// <param name="b">Second IP address</param>
	/// <param name="mask">Subnet mask length</param>
	/// <returns>Whether two IP addresses are in the same subnet</returns>
	/// <exception cref="ArgumentException">Subnet mask length is not greater or equal to 0</exception>
	// ReSharper disable once InconsistentNaming
	public static bool CheckCIDR(IPAddress a, IPAddress b, int mask)
	{
		if (a.AddressFamily != b.AddressFamily)
			return false;

		switch (mask)
		{
			case 0:
				return true;

			case < 0:
				throw new ArgumentException(nameof(mask));

			case 32 when a.AddressFamily == AddressFamily.InterNetwork:
			case 128 when a.AddressFamily == AddressFamily.InterNetworkV6:
				return a.Equals(b);
		}

		var aBytes = a.GetAddressBytes();
		var bBytes = b.GetAddressBytes();

		if (mask > aBytes.Length * 8)
			mask = aBytes.Length * 8;

		for (var i = 0; i < aBytes.Length; i++)
		{
			var diff = mask - (i * 8);

			switch (diff)
			{
				case 0:
					return true;

				case >= 8 when aBytes[i] != bBytes[i]:
					return false;

				case >= 8:
					continue;

				default:
					{
						var m = (byte)(0xFF << (8 - diff));
						return (aBytes[i] & m) == (bBytes[i] & m);
					}
			}
		}

		return true;
	}
}