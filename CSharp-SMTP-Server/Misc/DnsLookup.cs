using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;

namespace CSharp_SMTP_Server.Misc;

internal static class DnsLookup
{
	private static readonly LookupClient LookupClient = new();

	internal static async Task<List<string>> QueryTxtRecordsAsync(string domain, CancellationToken cancellationToken = default(CancellationToken))
	{
		var records = (await LookupClient.QueryAsync(domain, QueryType.TXT, cancellationToken: cancellationToken)).Answers.TxtRecords();
		var list = new List<string>();

		foreach (var record in records)
			list.Add(string.Concat(record.Text));

		return list;
	}

	internal static async Task<string?> QueryTxtRecordWithPrefixAsync(string domain, string prefix, CancellationToken cancellationToken = default(CancellationToken))
	{
		var records = (await LookupClient.QueryAsync(domain, QueryType.TXT, cancellationToken: cancellationToken)).Answers.TxtRecords();

		foreach (var record in records)
		{
			var text = string.Concat(record.Text);
			if (text.StartsWith(prefix, StringComparison.Ordinal))
				return text;
		}

		return null;
	}
}