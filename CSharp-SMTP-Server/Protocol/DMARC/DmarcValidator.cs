using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Misc;
using DnsClient;
using DnsClient.Protocol;

namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// DMARC validator
/// </summary>
public class DmarcValidator
{
	/// <summary>
	/// Maximum number of labels of DNS Tree Walk targets after the first query (RFC 9989, section 4.10).
	/// Limits the walk to 8 DNS queries.
	/// </summary>
	private const int TreeWalkMaxLabels = 7;

	private readonly SMTPServer _server;

	/// <summary>
	/// Hashset containing Public Suffix List
	/// </summary>
	// ReSharper disable once MemberCanBePrivate.Global
	public HashSet<string>? PublicSuffixes;

	#region Constructors
	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="server">SMTP server which configuration should be used</param>
	public DmarcValidator(SMTPServer server)
	{
		_server = server;
	}
	#endregion

	private bool UseTreeWalk => _server.Options.MailAuthenticationOptions.DmarcOptions.OrganizationalDomainDiscovery == OrganizationalDomainDiscovery.DnsTreeWalk;

	internal void Start()
	{
		if (UseTreeWalk || PublicSuffixes != null)
			return;

		if (!_server.Options.MailAuthenticationOptions.AutomaticallyDownloadPublicSuffixList)
			throw new Exception("Public suffix list is not loaded, but DMARC validation using Public Suffix List is enabled! Please enable automatic download of the list in the server options, manually load it before starting the server or switch to DNS Tree Walk.");

		DownloadList(_server.Options.MailAuthenticationOptions.PublicSuffixListUrl).Wait();
	}

	/// <summary>
	/// Downloads the Public Suffix List from the URL specified in server options.
	/// </summary>
	public async Task DownloadList() => await DownloadList(_server.Options.MailAuthenticationOptions.PublicSuffixListUrl);

	/// <summary>
	/// Downloads the Public Suffix List from the specified URL.
	/// </summary>
	/// <param name="url">Public Suffix List Download URL</param>
	// ReSharper disable once MemberCanBePrivate.Global
	public async Task DownloadList(string url)
	{
		PublicSuffixes ??= new();

		using var httpClient = new HttpClient();
		using var response = await httpClient.GetAsync(url);

		if (!response.IsSuccessStatusCode)
			throw new Exception("Failed to download list of domains!");

		var data = (await response.Content.ReadAsStringAsync()).Split(new [] {'\r', '\n'}, StringSplitOptions.RemoveEmptyEntries);

		PublicSuffixes.Clear();

		foreach (var line in data)
		{
			if (string.IsNullOrWhiteSpace(line) || line.StartsWith("//", StringComparison.Ordinal))
				continue;

			PublicSuffixes.Add(line);
		}
	}

	/// <summary>
	/// Returns the Organizational Domain determined using the Public Suffix List (RFC 7489).
	/// </summary>
	/// <param name="domain">Domain to process</param>
	/// <returns>Organizational Domain</returns>
	/// <exception cref="Exception">Returned if the Public Suffix List is not loaded.</exception>
	/// <seealso cref="GetOrganizationalDomainAsync"/>
	// ReSharper disable once MemberCanBePrivate.Global
	public string GetOrganizationalDomain(string domain)
	{
		if (PublicSuffixes == null)
			throw new Exception("Suffix list is null (not loaded)!");

		var sp = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);

		if (sp.Length <= 2)
			return domain;

		string orgDomain = sp[^2] + "." + sp[^1];
		int i = sp.Length - 2;

		while (PublicSuffixes.Contains(orgDomain) && i > 0)
		{
			i--;
			orgDomain = sp[i] + "." + orgDomain;
		}

		return orgDomain;
	}

	/// <summary>
	/// Returns the Organizational Domain determined using the method configured in <see cref="Config.DmarcOptions.OrganizationalDomainDiscovery"/>.
	/// </summary>
	/// <param name="domain">Domain to process</param>
	/// <returns>Organizational Domain</returns>
	public async Task<string> GetOrganizationalDomainAsync(string domain)
	{
		if (!UseTreeWalk)
			return GetOrganizationalDomain(domain);

		return (await TreeWalk(NormalizeDomain(domain), new Dictionary<string, DmarcLookup>())).OrganizationalDomain;
	}

	/// <summary>
	/// Validates Mail Transaction using DMARC
	/// </summary>
	/// <param name="transaction">Transaction to validate</param>
	/// <returns>Validation result</returns>
	/// <exception cref="Exception">Returned if Public Suffix List is used and it was never loaded.</exception>
	public async Task<ValidationResult> ValidateTransaction(MailTransaction transaction)
	{
		var fromDomain = GetFromDomain(transaction.GetFrom);

		if (fromDomain == null)
			return ValidationResult.None;

		fromDomain = NormalizeDomain(fromDomain);

		return UseTreeWalk
			? await ValidateUsingTreeWalk(transaction, fromDomain)
			: await ValidateUsingPublicSuffixList(transaction, fromDomain);
	}

	internal static string? GetFromDomain(string? address)
	{
		if (string.IsNullOrWhiteSpace(address))
			return null;

		var atIndex = address.LastIndexOf('@');
		if (atIndex <= 0 || atIndex == address.Length - 1)
			return null;

		var domain = address[(atIndex + 1)..];
		return domain.Contains('.', StringComparison.Ordinal) ? domain : null;
	}

	private static string NormalizeDomain(string domain) => string.Join(".", domain.Trim().ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries));

	#region RFC 7489 (Public Suffix List)
	private async Task<ValidationResult> ValidateUsingPublicSuffixList(MailTransaction transaction, string fromDomain)
	{
		if (PublicSuffixes == null)
			throw new Exception("Suffix list is not loaded!");

		var fromOrgDomain = GetOrganizationalDomain(fromDomain);
		var record = (await QueryDmarcRecord(fromDomain)).Record;
		var isSubdomain = false;

		if (record == null && !fromOrgDomain.Equals(fromDomain, StringComparison.OrdinalIgnoreCase))
		{
			record = (await QueryDmarcRecord(fromOrgDomain)).Record;
			isSubdomain = true;
		}

		if (record == null)
			return ValidationResult.None;

		var policy = ResolvePolicy(record, isSubdomain, false, false);

		if (policy == null)
			return ValidationResult.None;

		return await EvaluateAlignment(transaction, record, policy.Value, fromDomain, fromOrgDomain, domain => Task.FromResult(GetOrganizationalDomain(domain)));
	}
	#endregion

	#region RFC 9989 (DNS Tree Walk)
	private async Task<ValidationResult> ValidateUsingTreeWalk(MailTransaction transaction, string fromDomain)
	{
		// Caches DMARC records within the transaction, because Tree Walks for the SPF and DKIM domains usually overlap with the walk for the Author Domain
		var cache = new Dictionary<string, DmarcLookup>();
		var walk = await TreeWalk(fromDomain, cache);

		// No DMARC Policy Record - DMARC doesn't apply to the message
		if (walk.Records.Count == 0)
			return ValidationResult.None;

		DmarcRecord record;
		var isSubdomain = walk.Records[0].Key != fromDomain;

		if (!isSubdomain)
			record = walk.Records[0].Value; // Record published for the Author Domain
		else
		{
			// Record of the Organizational Domain or (if it doesn't have one) of the PSD
			record = (await LookupCached(walk.OrganizationalDomain, cache)).Record ?? walk.Records[^1].Value;
		}

		var nonExistent = isSubdomain && record.HasTag("np") && !await DomainExists(fromDomain, await LookupCached(fromDomain, cache));
		var policy = ResolvePolicy(record, isSubdomain, true, nonExistent);

		if (policy == null)
			return ValidationResult.None;

		return await EvaluateAlignment(transaction, record, policy.Value, fromDomain, walk.OrganizationalDomain,
			async domain => (await TreeWalk(NormalizeDomain(domain), cache)).OrganizationalDomain);
	}

	/// <summary>
	/// Performs DNS Tree Walk (RFC 9989, section 4.10).
	/// </summary>
	/// <param name="domain">Normalized domain to start the walk at</param>
	/// <param name="cache">Cache of DMARC records</param>
	/// <returns>DMARC records found (ordered from the longest domain) and the Organizational Domain</returns>
	private static async Task<TreeWalkResult> TreeWalk(string domain, Dictionary<string, DmarcLookup> cache)
	{
		var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
		var records = new List<KeyValuePair<string, DmarcRecord>>();
		var count = labels.Length;

		while (count > 0)
		{
			var target = string.Join(".", labels, labels.Length - count, count);
			var record = (await LookupCached(target, cache)).Record;

			if (record != null)
			{
				records.Add(new KeyValuePair<string, DmarcRecord>(target, record));

				if (record.IsPublicSuffixDomain || record.IsNotPublicSuffixDomain)
					break;
			}

			// Long domains are shortened to 7 labels after the first query, so the walk never exceeds 8 queries
			count = Math.Min(count - 1, TreeWalkMaxLabels);
		}

		return new TreeWalkResult(records, DetermineOrganizationalDomain(domain, labels, records));
	}

	/// <summary>
	/// Selects the Organizational Domain from the Tree Walk results (RFC 9989, section 4.10.2).
	/// </summary>
	private static string DetermineOrganizationalDomain(string domain, string[] labels, List<KeyValuePair<string, DmarcRecord>> records)
	{
		// If no DMARC record was found, the initial target domain is the Organizational Domain
		if (records.Count == 0)
			return domain;

		// The walk stops at the first record containing "psd" tag set to "y" or "n", so only the last record has to be checked.
		// If no such record was found, the last record is the one with the fewest number of labels.
		var last = records[^1];

		// "psd=y" (other than for the starting domain) - the Organizational Domain is one label below the PSD
		if (last.Value.IsPublicSuffixDomain && last.Key != domain)
		{
			var psdLabels = last.Key.Split('.', StringSplitOptions.RemoveEmptyEntries).Length;
			return string.Join(".", labels, labels.Length - psdLabels - 1, psdLabels + 1);
		}

		// "psd=n" or the record with the fewest number of labels
		return last.Key;
	}

	/// <summary>
	/// Checks if the domain exists (doesn't return NXDOMAIN).
	/// </summary>
	private static async Task<bool> DomainExists(string domain, DmarcLookup dmarcLookup)
	{
		// _dmarc.domain exists or the query returned a different error - the domain itself exists (or can't be proven not to exist)
		if (dmarcLookup.ResponseCode != DnsHeaderResponseCode.NotExistentDomain)
			return true;

		var response = await DnsLookup.LookupClient.QueryAsync(domain, QueryType.A);
		return response.Header.ResponseCode != DnsHeaderResponseCode.NotExistentDomain;
	}

	private static async Task<DmarcLookup> LookupCached(string domain, Dictionary<string, DmarcLookup> cache)
	{
		if (cache.TryGetValue(domain, out var lookup))
			return lookup;

		lookup = await QueryDmarcRecord(domain);
		cache[domain] = lookup;
		return lookup;
	}

	private sealed class TreeWalkResult
	{
		internal readonly List<KeyValuePair<string, DmarcRecord>> Records;
		internal readonly string OrganizationalDomain;

		internal TreeWalkResult(List<KeyValuePair<string, DmarcRecord>> records, string organizationalDomain)
		{
			Records = records;
			OrganizationalDomain = organizationalDomain;
		}
	}
	#endregion

	#region Shared
	private sealed class DmarcLookup
	{
		internal readonly DmarcRecord? Record;
		internal readonly DnsHeaderResponseCode ResponseCode;

		internal DmarcLookup(DmarcRecord? record, DnsHeaderResponseCode responseCode)
		{
			Record = record;
			ResponseCode = responseCode;
		}
	}

	/// <summary>
	/// Queries DMARC Policy Record of the domain.
	/// If multiple DMARC records are published, all of them are discarded.
	/// </summary>
	private static async Task<DmarcLookup> QueryDmarcRecord(string domain)
	{
		var response = await DnsLookup.LookupClient.QueryAsync("_dmarc." + domain, QueryType.TXT);
		DmarcRecord? found = null;
		var count = 0;

		foreach (var answer in response.Answers)
		{
			if (answer is not TxtRecord txt)
				continue;

			var record = DmarcRecord.Parse(string.Concat(txt.Text));
			if (record == null)
				continue;

			found = record;
			count++;
		}

		return new DmarcLookup(count == 1 ? found : null, response.Header.ResponseCode);
	}

	/// <summary>
	/// Selects the Domain Owner Assessment Policy from the record.
	/// </summary>
	/// <param name="record">DMARC Policy Record</param>
	/// <param name="isSubdomain">Indicates whether the record was not published for the Author Domain</param>
	/// <param name="supportsNp">Indicates whether "np" tag is supported</param>
	/// <param name="nonExistent">Indicates whether the Author Domain doesn't exist</param>
	/// <returns>Policy or null if DMARC processing should not be applied</returns>
	private static DmarcResult? ResolvePolicy(DmarcRecord record, bool isSubdomain, bool supportsNp, bool nonExistent)
	{
		var p = record.GetPolicy("p", out var invalid);
		var sp = record.GetPolicy("sp", out var spInvalid);
		DmarcResult? np = null;
		var npInvalid = false;

		if (supportsNp)
			np = record.GetPolicy("np", out npInvalid);

		// Invalid policy tags - if "rua" is present, act as if "p=none" was retrieved, otherwise don't apply DMARC
		if (invalid || spInvalid || npInvalid)
			return record.HasTag("rua") ? DmarcResult.None : null;

		// Missing "p" tag is treated as "p=none"
		var policy = p ?? DmarcResult.None;

		if (!isSubdomain)
			return policy;

		return nonExistent ? np ?? sp ?? policy : sp ?? policy;
	}

	private static async Task<ValidationResult> EvaluateAlignment(MailTransaction transaction, DmarcRecord record, DmarcResult policy, string fromDomain, string fromOrgDomain, Func<string, Task<string>> getOrganizationalDomain)
	{
		if (transaction.SPFValidationResult == ValidationResult.Pass)
		{
			if (fromDomain.Equals(NormalizeDomain(transaction.FromDomain), StringComparison.OrdinalIgnoreCase))
				return ValidationResult.Pass; //SPF Aligned (strict)

			if (record.GetAlignmentMode("aspf") == AlignmentMode.Relaxed && await IsRelaxedAligned(transaction.FromDomain, fromOrgDomain, getOrganizationalDomain))
				return ValidationResult.Pass; //SPF Aligned (relaxed)
		}

		if (transaction.DKIMValidationResult.ValidationResult == ValidationResult.Pass)
		{
			var dkimDomain = transaction.DKIMValidationResult.Domain!;

			if (fromDomain.Equals(NormalizeDomain(dkimDomain), StringComparison.OrdinalIgnoreCase))
				return ValidationResult.Pass; //DKIM Aligned (strict)

			if (record.GetAlignmentMode("adkim") == AlignmentMode.Relaxed && await IsRelaxedAligned(dkimDomain, fromOrgDomain, getOrganizationalDomain))
				return ValidationResult.Pass; //DKIM Aligned (relaxed)
		}

		return policy switch
		{
			DmarcResult.Quarantine => ValidationResult.Softfail,
			DmarcResult.Reject => ValidationResult.Fail,
			_ => ValidationResult.None
		};
	}

	private static async Task<bool> IsRelaxedAligned(string domain, string fromOrgDomain, Func<string, Task<string>> getOrganizationalDomain)
	{
		domain = NormalizeDomain(domain);

		// The Organizational Domain is always the domain itself or its parent,
		// so the domains can't be aligned if the domain isn't within the From Organizational Domain (avoids unnecessary DNS queries).
		if (!domain.Equals(fromOrgDomain, StringComparison.OrdinalIgnoreCase) && !domain.EndsWith("." + fromOrgDomain, StringComparison.OrdinalIgnoreCase))
			return false;

		return (await getOrganizationalDomain(domain)).Equals(fromOrgDomain, StringComparison.OrdinalIgnoreCase);
	}
	#endregion
}
