using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;

namespace CSharp_SMTP_Server.Misc;

internal static class DnsLookup
{
	internal static readonly LookupClient LookupClient = new();

	internal static async Task<List<string>> QueryTxtRecordsAsync(string domain, CancellationToken cancellationToken = default(CancellationToken))
	{
		var records = (await LookupClient.QueryAsync(domain, QueryType.TXT, cancellationToken: cancellationToken)).Answers;
		var list = new List<string>();

		foreach (var record in records)
			if (record is TxtRecord ar)
				list.Add(string.Concat(ar.Text));

		return list;
	}

	internal static async Task<string?> QueryTxtRecordWithPrefixAsync(string domain, string prefix, CancellationToken cancellationToken = default(CancellationToken))
	{
		var records = (await LookupClient.QueryAsync(domain, QueryType.TXT, cancellationToken: cancellationToken)).Answers;

		foreach (var record in records)
		{
			if (record is not TxtRecord ar)
				continue;

			var text = string.Concat(ar.Text);
			if (text.StartsWith(prefix, StringComparison.Ordinal))
				return text;
		}

		return null;
	}
}