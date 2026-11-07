using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Misc;
using DnsClient;
using DnsClient.Protocol;

// ReSharper disable MemberCanBePrivate.Global

namespace CSharp_SMTP_Server.Protocol.SPF;

/// <summary>
/// SPF validator
/// </summary>
public static class SpfValidator
{
	/// <summary>
	/// Maximum number of mechanisms and modifiers causing DNS lookups during a single evaluation (RFC 7208, section 4.6.4)
	/// </summary>
	private const int MaxDnsLookups = 10;

	/// <summary>
	/// Maximum number of DNS lookups returning no records during a single evaluation (RFC 7208, section 4.6.4)
	/// </summary>
	private const int MaxVoidLookups = 2;

	/// <summary>
	/// Maximum number of MX or PTR names processed by a single "mx" or "ptr" mechanism (RFC 7208, section 4.6.4)
	/// </summary>
	private const int MaxNamesPerMechanism = 10;

	/// <summary>
	/// RFC 7208 (SPF) check_host() function
	/// Authenticates remote SMTP server.
	/// </summary>
	/// <param name="ipAddress">IP address of the remote SMTP server</param>
	/// <param name="domain">Email sender domain</param>
	/// <returns>SPF validation result</returns>
	public static async Task<ValidationResult> CheckHost(IPAddress ipAddress, string domain)
	{
		if (ipAddress.IsIPv4MappedToIPv6)
			ipAddress = ipAddress.MapToIPv4();

		try
		{
			// One state object is shared by the whole evaluation (including all nested "include" and "redirect" records),
			// so the lookup limits apply to the evaluation as a whole.
			return await Evaluate(ipAddress, domain, new EvaluationState());
		}
		catch (SpfEvaluationException e)
		{
			return e.Result;
		}
		catch (ArgumentException)
		{
			// Invalid domain name in the record
			return ValidationResult.Permerror;
		}
		catch (Exception)
		{
			// DNS timeouts and other DNS failures
			return ValidationResult.Temperror;
		}
	}

	private static async Task<ValidationResult> Evaluate(IPAddress ipAddress, string domain, EvaluationState state)
	{
		var record = await GetSpfRecord(domain);

		if (record == null)
			return ValidationResult.None;

		string? redirect = null;

		foreach (var term in record[6..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
		{
			var equalsIndex = term.IndexOf('=');
			var colonIndex = term.IndexOf(':');
			var slashIndex = term.IndexOf('/');

			// Modifier (name=value)
			if (equalsIndex > 0 && (colonIndex == -1 || equalsIndex < colonIndex) && (slashIndex == -1 || equalsIndex < slashIndex))
			{
				if (term[..equalsIndex].Equals("redirect", StringComparison.OrdinalIgnoreCase))
				{
					if (redirect != null)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					redirect = term[(equalsIndex + 1)..];
				}

				// Other modifiers (eg. "exp") are ignored
				continue;
			}

			var qualifier = ValidationResult.Pass;
			var mechanism = term;

			switch (term[0])
			{
				case '+':
					mechanism = term[1..];
					break;

				case '-':
					qualifier = ValidationResult.Fail;
					mechanism = term[1..];
					break;

				case '~':
					qualifier = ValidationResult.Softfail;
					mechanism = term[1..];
					break;

				case '?':
					qualifier = ValidationResult.Neutral;
					mechanism = term[1..];
					break;
			}

			string? cidr = null;
			slashIndex = mechanism.IndexOf('/');
			if (slashIndex != -1)
			{
				cidr = mechanism[slashIndex..];
				mechanism = mechanism[..slashIndex];
			}

			string? argument = null;
			colonIndex = mechanism.IndexOf(':');
			if (colonIndex != -1)
			{
				argument = mechanism[(colonIndex + 1)..];
				mechanism = mechanism[..colonIndex];

				if (argument.Length == 0)
					throw new SpfEvaluationException(ValidationResult.Permerror);
			}

			switch (mechanism.ToLowerInvariant())
			{
				case "all":
					return qualifier;

				case "include":
				{
					if (argument == null)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					CountDnsLookup(state);

					switch (await Evaluate(ipAddress, argument, state))
					{
						case ValidationResult.Pass:
							return qualifier;

						case ValidationResult.Temperror:
							return ValidationResult.Temperror;

						case ValidationResult.Permerror:
						case ValidationResult.None:
							throw new SpfEvaluationException(ValidationResult.Permerror);
					}

					break;
				}

				case "a":
				{
					CountDnsLookup(state);
					ParseDualCidr(cidr, out var ip4Cidr, out var ip6Cidr);

					if (await MatchesAddressRecords(ipAddress, argument ?? domain, ip4Cidr, ip6Cidr, state, true))
						return qualifier;

					break;
				}

				case "mx":
				{
					CountDnsLookup(state);
					ParseDualCidr(cidr, out var ip4Cidr, out var ip6Cidr);

					var response = await Query(argument ?? domain, QueryType.MX);
					var exchanges = response.Answers.OfType<MxRecord>().Select(mx => mx.Exchange.Value.TrimEnd('.')).Where(mx => mx.Length > 0).ToList();

					if (exchanges.Count == 0)
					{
						CountVoidLookup(state);
						break;
					}

					if (exchanges.Count > MaxNamesPerMechanism)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					foreach (var exchange in exchanges)
					{
						if (await MatchesAddressRecords(ipAddress, exchange, ip4Cidr, ip6Cidr, state, false))
							return qualifier;
					}

					break;
				}

				case "ptr":
				{
					CountDnsLookup(state);

					if (cidr != null)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					if (await MatchesPtr(ipAddress, argument ?? domain, state))
						return qualifier;

					break;
				}

				case "ip4":
				{
					if (argument == null || !IPAddress.TryParse(argument, out var network) || network.AddressFamily != AddressFamily.InterNetwork)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					var prefix = ParsePrefix(cidr, 32);

					if (ipAddress.AddressFamily == AddressFamily.InterNetwork && CheckCIDR(ipAddress, network, prefix))
						return qualifier;

					break;
				}

				case "ip6":
				{
					if (argument == null || !IPAddress.TryParse(argument, out var network) || network.AddressFamily != AddressFamily.InterNetworkV6)
						throw new SpfEvaluationException(ValidationResult.Permerror);

					var prefix = ParsePrefix(cidr, 128);

					if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6 && CheckCIDR(ipAddress, network, prefix))
						return qualifier;

					break;
				}

				// "exists" (which requires macros support) and unknown mechanisms are ignored
			}
		}

		// "redirect" is evaluated only if no mechanism matched (RFC 7208, section 6.1), regardless of its position in the record
		if (redirect != null)
		{
			if (redirect.Length == 0)
				throw new SpfEvaluationException(ValidationResult.Permerror);

			CountDnsLookup(state);

			var result = await Evaluate(ipAddress, redirect, state);
			return result == ValidationResult.None ? ValidationResult.Permerror : result;
		}

		return ValidationResult.Neutral;
	}

	/// <summary>
	/// Returns the SPF record of the domain, null if the domain doesn't have one.
	/// </summary>
	private static async Task<string?> GetSpfRecord(string domain)
	{
		var response = await Query(domain, QueryType.TXT);
		string? record = null;

		foreach (var txt in response.Answers.OfType<TxtRecord>())
		{
			var text = string.Concat(txt.Text);

			if (!text.Equals("v=spf1", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase))
				continue;

			// RFC 7208, section 4.5: multiple SPF records result in a permerror
			if (record != null)
				throw new SpfEvaluationException(ValidationResult.Permerror);

			record = text;
		}

		return record;
	}

	/// <summary>
	/// Checks if any A/AAAA record of the domain matches the IP address
	/// </summary>
	private static async Task<bool> MatchesAddressRecords(IPAddress ipAddress, string domain, int ip4Cidr, int ip6Cidr, EvaluationState state, bool countVoidLookup)
	{
		var isIpv4 = ipAddress.AddressFamily == AddressFamily.InterNetwork;
		var response = await Query(domain, isIpv4 ? QueryType.A : QueryType.AAAA);
		var addresses = response.Answers.OfType<AddressRecord>().Select(a => a.Address).Where(a => a.AddressFamily == ipAddress.AddressFamily).ToList();

		if (addresses.Count == 0)
		{
			if (countVoidLookup)
				CountVoidLookup(state);

			return false;
		}

		var prefix = isIpv4 ? ip4Cidr : ip6Cidr;
		return addresses.Any(address => CheckCIDR(address, ipAddress, prefix));
	}

	/// <summary>
	/// "ptr" mechanism (RFC 7208, section 5.5)
	/// </summary>
	private static async Task<bool> MatchesPtr(IPAddress ipAddress, string targetDomain, EvaluationState state)
	{
		List<string> names;

		try
		{
			var response = await DnsLookup.LookupClient.QueryReverseAsync(ipAddress);
			names = response.Answers.OfType<PtrRecord>().Select(ptr => ptr.PtrDomainName.Value.TrimEnd('.')).Where(name => name.Length > 0).Take(MaxNamesPerMechanism).ToList();
		}
		catch (Exception e) when (e is not SpfEvaluationException)
		{
			// A DNS error during the PTR lookup means the mechanism doesn't match
			return false;
		}

		if (names.Count == 0)
		{
			CountVoidLookup(state);
			return false;
		}

		targetDomain = targetDomain.TrimEnd('.');

		foreach (var name in names)
		{
			if (!name.Equals(targetDomain, StringComparison.OrdinalIgnoreCase) && !name.EndsWith("." + targetDomain, StringComparison.OrdinalIgnoreCase))
				continue;

			try
			{
				// The name is validated only if it resolves back to the IP address
				if (await MatchesAddressRecords(ipAddress, name, 32, 128, state, false))
					return true;
			}
			catch (Exception e) when (e is not SpfEvaluationException)
			{
				// A DNS error during the address lookup means this name is skipped
			}
		}

		return false;
	}

	/// <summary>
	/// Performs a DNS query. Errors other than "name does not exist" result in a temperror (RFC 7208, section 4.4).
	/// </summary>
	private static async Task<IDnsQueryResponse> Query(string name, QueryType type)
	{
		var response = await DnsLookup.LookupClient.QueryAsync(name, type);

		if (response.HasError && response.Header.ResponseCode != DnsHeaderResponseCode.NotExistentDomain)
			throw new SpfEvaluationException(ValidationResult.Temperror);

		return response;
	}

	private static void CountDnsLookup(EvaluationState state)
	{
		if (++state.DnsLookups > MaxDnsLookups)
			throw new SpfEvaluationException(ValidationResult.Permerror);
	}

	private static void CountVoidLookup(EvaluationState state)
	{
		if (++state.VoidLookups > MaxVoidLookups)
			throw new SpfEvaluationException(ValidationResult.Permerror);
	}

	/// <summary>
	/// Parses "/prefix" CIDR length.
	/// </summary>
	private static int ParsePrefix(string? cidr, int max)
	{
		if (cidr == null)
			return max;

		if (cidr.Length < 2 || !int.TryParse(cidr.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) || prefix > max)
			throw new SpfEvaluationException(ValidationResult.Permerror);

		return prefix;
	}

	/// <summary>
	/// Parses dual CIDR length ("/ip4-prefix", "//ip6-prefix" or "/ip4-prefix//ip6-prefix")
	/// </summary>
	private static void ParseDualCidr(string? cidr, out int ip4Cidr, out int ip6Cidr)
	{
		ip4Cidr = 32;
		ip6Cidr = 128;

		if (cidr == null)
			return;

		var dualIndex = cidr.IndexOf("//", StringComparison.Ordinal);

		if (dualIndex == -1)
			ip4Cidr = ParsePrefix(cidr, 32);
		else
		{
			if (dualIndex > 0)
				ip4Cidr = ParsePrefix(cidr[..dualIndex], 32);

			ip6Cidr = ParsePrefix(cidr[(dualIndex + 1)..], 128);
		}
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

	/// <summary>
	/// State shared by the whole SPF evaluation
	/// </summary>
	private sealed class EvaluationState
	{
		public int DnsLookups;
		public int VoidLookups;
	}

	/// <summary>
	/// Terminates the evaluation with the specified result
	/// </summary>
	private sealed class SpfEvaluationException : Exception
	{
		public SpfEvaluationException(ValidationResult result) => Result = result;

		public readonly ValidationResult Result;
	}
}
