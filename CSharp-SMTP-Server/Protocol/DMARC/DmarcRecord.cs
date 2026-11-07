using System;
using System.Collections.Generic;

namespace CSharp_SMTP_Server.Protocol.DMARC;

/// <summary>
/// Parsed DMARC Policy Record
/// </summary>
internal sealed class DmarcRecord
{
	private readonly Dictionary<string, string> _tags;

	private DmarcRecord(Dictionary<string, string> tags)
	{
		_tags = tags;
	}

	/// <summary>
	/// Parses a DMARC Policy Record.
	/// </summary>
	/// <param name="text">TXT record content</param>
	/// <returns>Parsed record or null if the text is not a DMARC Policy Record</returns>
	internal static DmarcRecord? Parse(string text)
	{
		var parts = text.Split(';');

		// The version tag must be the first one, otherwise the entire record is ignored.
		if (!IsVersionTag(parts[0]))
			return null;

		var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		for (var i = 1; i < parts.Length; i++)
		{
			var eq = parts[i].IndexOf('=');
			if (eq < 0)
				continue; // Syntax errors are ignored

			var name = parts[i][..eq].Trim();
			if (name.Length == 0)
				continue;

			tags.TryAdd(name, parts[i][(eq + 1)..].Trim());
		}

		return new DmarcRecord(tags);
	}

	private static bool IsVersionTag(string part)
	{
		var eq = part.IndexOf('=');
		return eq >= 0 &&
		       part[..eq].Trim().Equals("v", StringComparison.OrdinalIgnoreCase) &&
		       part[(eq + 1)..].Trim().Equals("DMARC1", StringComparison.Ordinal);
	}

	internal string? GetTag(string name) => _tags.TryGetValue(name, out var value) ? value : null;

	internal bool HasTag(string name) => _tags.ContainsKey(name);

	/// <summary>
	/// Indicates whether the record contains "psd=y" tag.
	/// </summary>
	internal bool IsPublicSuffixDomain => "y".Equals(GetTag("psd"), StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Indicates whether the record contains "psd=n" tag.
	/// </summary>
	internal bool IsNotPublicSuffixDomain => "n".Equals(GetTag("psd"), StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Indicates whether the given alignment tag ("aspf" or "adkim") requests strict alignment.
	/// </summary>
	internal AlignmentMode GetAlignmentMode(string name) => "s".Equals(GetTag(name), StringComparison.OrdinalIgnoreCase) ? AlignmentMode.Strict : AlignmentMode.Relaxed;

	/// <summary>
	/// Returns value of a policy tag ("p", "sp" or "np").
	/// </summary>
	/// <param name="name">Tag name</param>
	/// <param name="invalid">Set to true if the tag is present, but its value is not valid</param>
	/// <returns>Policy or null if the tag is absent or invalid</returns>
	internal DmarcResult? GetPolicy(string name, out bool invalid)
	{
		invalid = false;
		var value = GetTag(name);

		if (value == null)
			return null;

		if (value.Equals("none", StringComparison.OrdinalIgnoreCase))
			return DmarcResult.None;

		if (value.Equals("quarantine", StringComparison.OrdinalIgnoreCase))
			return DmarcResult.Quarantine;

		if (value.Equals("reject", StringComparison.OrdinalIgnoreCase))
			return DmarcResult.Reject;

		invalid = true;
		return null;
	}
}
