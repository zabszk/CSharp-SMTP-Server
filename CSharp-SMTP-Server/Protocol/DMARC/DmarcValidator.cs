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
public class DmarcValidator
{
	private readonly SMTPServer _server;

	private static readonly HashSet<string> PublicSuffixes = new();
	private static bool _publicSuffixesLoaded;
	private static readonly object PublicSuffixesLock = new();

	#region Constructors
	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="server">SMTP server which configuration should be used</param>
	public DmarcValidator(SMTPServer server)
	{
		_server = server;

		if (!_publicSuffixesLoaded)
			DownloadList(_server.Options.PublicSuffixList).Wait();
	}
	#endregion

	/// <summary>
	/// Forces PublicSuffixes reload
	/// </summary>
	/// <param name="url">URL of the list</param>
	public async Task ForceRefreshList(string? url = null) => await DownloadList(url ?? _server.Options.PublicSuffixList, true);

	private static async Task DownloadList(string url, bool force = false)
	{
		if (!force)
		{
			lock (PublicSuffixesLock)
			{
				if (_publicSuffixesLoaded)
					return;

				_publicSuffixesLoaded = true;
			}
		}
		else _publicSuffixesLoaded = true;

		try
		{
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
		catch (Exception)
		{
			_publicSuffixesLoaded = false;
			throw;
		}
	}

	/// <summary>
	/// Returns the Organizational Domain
	/// </summary>
	/// <param name="domain">Domain to process</param>
	/// <returns>Organizational Domain</returns>
	/// <exception cref="Exception">Returned if DMARC Validator was never initialized.</exception>
	// ReSharper disable once MemberCanBePrivate.Global
	public static string GetOrganizationalDomain(string domain)
	{
		if (!_publicSuffixesLoaded)
			throw new Exception("Suffix list is not loaded, because DMARC Validator was never initialized.");

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
		if (!_publicSuffixesLoaded)
			throw new Exception("Suffix list is not loaded, because DMARC Validator was never initialized.");

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

	private static ValidationResult ProcessRecord(MailTransaction transaction, string record, string fromDomain, string fromOrgDomain, bool isSubdomain)
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