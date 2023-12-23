using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol.Commands;
using DnsClient.Data.Records;
using DnsClient.Enums;

namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// DMARC validator
/// </summary>
public class DmarcValidator : IMailValidator
{
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

	internal void Start()
	{
		if (PublicSuffixes != null)
			return;

		if (!_server.Options.MailAuthenticationOptions.AutomaticallyDownloadPublicSuffixList)
			throw new Exception("Public suffix list is not loaded, but DMARC validation is enabled! Please enable automatic download of the list in the server options or manually load it before starting the server.");

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
	/// Returns the Organizational Domain
	/// </summary>
	/// <param name="domain">Domain to process</param>
	/// <returns>Organizational Domain</returns>
	/// <exception cref="Exception">Returned if DMARC Validator was never initialized.</exception>
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
	/// Validates Mail Transaction using DMARC
	/// </summary>
	/// <param name="transaction">Transaction to validate</param>
	/// <returns>Validation result</returns>
	/// <exception cref="Exception">Returned if DMARC Validator was never initialized.</exception>
	public async Task<ValidationResult> ValidateTransaction(MailTransaction transaction)
	{
		if (PublicSuffixes == null)
			throw new Exception("Suffix list is not loaded!.");

		var from = transaction.GetFrom;

		if (from == null)
			return ValidationResult.None;

		TransactionCommands.ProcessAddress(from, out var fromDomain);

		if (fromDomain == null)
			return ValidationResult.None;

		var record = await GetDmarcRecord(fromDomain);
		var fromOrgDomain = GetOrganizationalDomain(fromDomain);
		bool isSubdomain = record == null;

		record ??= await GetDmarcRecord(fromOrgDomain);

		return record != null ? ProcessRecord(transaction, record, fromDomain, fromOrgDomain, isSubdomain) : ValidationResult.None;
	}

	private async Task<string?> GetDmarcRecord(string domain)
	{
		var dmarcQuery = await _server.DnsClient!.Query("_dmarc." + domain, QType.TXT);

		if (dmarcQuery.ErrorCode != DnsErrorCode.NoError || dmarcQuery.Records == null)
			return null;

		string? record = null;

		foreach (var r in dmarcQuery.Records)
		{
			if (r is not DnsRecord.TXTRecord t || !t.Text.StartsWith("v=DMARC1;", StringComparison.Ordinal))
				continue;

			if (record != null)
				return null;

			record = t.Text;
		}

		return record;
	}

	private ValidationResult ProcessRecord(MailTransaction transaction, string record, string fromDomain, string fromOrgDomain, bool isSubdomain)
	{
		record = record[8..].Trim().Replace("; ", ";", StringComparison.Ordinal);

		var aspf = record.Contains("aspf=s", StringComparison.OrdinalIgnoreCase) ? AlignmentMode.Strict : AlignmentMode.Relaxed;
		var action = DmarcResult.None;

		if (isSubdomain && record.Contains(";sp=", StringComparison.OrdinalIgnoreCase))
		{
			if (record.Contains(";sp=reject", StringComparison.OrdinalIgnoreCase)) action = DmarcResult.Reject;
			else if (record.Contains(";sp=quarantine", StringComparison.OrdinalIgnoreCase)) action = DmarcResult.Quarantine;
		}
		else
		{
			if (record.Contains(";p=reject", StringComparison.OrdinalIgnoreCase)) action = DmarcResult.Reject;
			else if (record.Contains(";p=quarantine", StringComparison.OrdinalIgnoreCase)) action = DmarcResult.Quarantine;
		}

		bool isAligned = fromDomain.Equals(transaction.FromDomain, StringComparison.OrdinalIgnoreCase);

		if (!isAligned && aspf == AlignmentMode.Relaxed)
		{
			var envelopeFromOrgDomain = GetOrganizationalDomain(transaction.FromDomain);
			isAligned = fromOrgDomain.Equals(envelopeFromOrgDomain, StringComparison.OrdinalIgnoreCase);
		}

		if (isAligned)
			return ValidationResult.Pass;

		return action switch
		{
			DmarcResult.Quarantine => ValidationResult.Softfail,
			DmarcResult.Reject => ValidationResult.Fail,
			_ => ValidationResult.None
		};
	}
}