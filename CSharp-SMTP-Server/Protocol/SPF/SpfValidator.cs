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

public class SpfValidator
{
	private readonly DnsClient.DnsClient _dnsClient;

	public SpfValidator(SMTPServer server) : this(server.Options.DnsServerEndpoint, new DnsLogger(server)) { }

	public SpfValidator(DnsClient.DnsClient dnsClient) => _dnsClient = dnsClient;

	public SpfValidator(EndPoint dnsServerEndpoint, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerEndpoint, dnsClientOptions)) { }

	public SpfValidator(EndPoint dnsServerEndpoint, IErrorLogging? errorLogging) : this(dnsServerEndpoint, new DnsClientOptions {ErrorLogging = errorLogging}) { }

	public SpfValidator(IPAddress dnsServerAddress, ushort dnsServerPort = 53, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerAddress, dnsServerPort, dnsClientOptions)) { }

	public SpfValidator(string dnsServerAddress, ushort dnsServerPort = 53, DnsClientOptions? dnsClientOptions = null) : this(new DnsClient.DnsClient(dnsServerAddress, dnsServerPort, dnsClientOptions)) { }

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

	// ReSharper disable once InconsistentNaming
	private static bool CheckCIDR(IPAddress a, IPAddress b, int mask)
	{
		if (a.AddressFamily != b.AddressFamily)
			return false;

		if ((mask == 32 && a.AddressFamily == AddressFamily.InterNetwork) || (mask == 128 && a.AddressFamily == AddressFamily.InterNetworkV6))
			return a.Equals(b);

		var aBytes = a.GetAddressBytes();
		var bBytes = b.GetAddressBytes();

		if (mask > aBytes.Length * 8)
			mask = aBytes.Length * 8;

		for (var i = 0; i < aBytes.Length; i++)
		{
			var diff = mask - (i * 8);

			if (diff == 0)
				return true;

			if (diff >= 8)
			{
				if (aBytes[i] != bBytes[i])
					return false;
				continue;
			}

			byte m = (byte)(0xFF << (8 - diff));
			return (aBytes[i] & m) == (bBytes[i] & m);
		}

		return true;
	}
}