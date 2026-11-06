using System;
using System.Diagnostics.CodeAnalysis;

namespace CSharp_SMTP_Server.Protocol;

/// <summary>
/// Syntax validation of envelope addresses and domains (RFC 5321, section 4.1.2).
/// </summary>
internal static class AddressSyntax
{
	/// <summary>
	/// Extracts and validates the address from a MAIL FROM / RCPT TO argument, e.g. <c>:&lt;user@example.com&gt; SIZE=1000</c>.
	/// </summary>
	/// <param name="data">Command argument</param>
	/// <param name="maxAddressLength">Maximum length of the whole address</param>
	/// <param name="maxDomainLength">Maximum length of the domain</param>
	/// <param name="domain">Domain of the address, null if the address is invalid</param>
	/// <returns>Validated address or null if the argument is invalid</returns>
	internal static string? ParsePath(string? data, uint maxAddressLength, uint maxDomainLength, out string? domain)
	{
		domain = null;
		if (data == null)
			return null;

		var path = data.Trim();
		if (path.StartsWith(':'))
			path = path[1..].TrimStart();

		if (path.Length == 0 || path[0] != '<')
			return null;

		var close = path.IndexOf('>');
		if (close == -1)
			return null;

		// Only space-separated ESMTP parameters may follow the path
		if (close + 1 < path.Length && path[close + 1] != ' ')
			return null;

		var address = path[1..close];
		if (address.Length == 0 || address.Length > maxAddressLength)
			return null;

		var at = address.LastIndexOf('@');
		if (at <= 0 || !IsValidLocalPart(address.AsSpan(0, at)))
			return null;

		var addressDomain = address[(at + 1)..];
		if (addressDomain.Length > maxDomainLength || !IsValidDomain(addressDomain))
			return null;

		domain = addressDomain;
		return address;
	}

	/// <summary>
	/// Checks if the value is a syntactically valid, fully qualified domain name (LDH labels, at least two labels).
	/// </summary>
	internal static bool IsValidDomain([NotNullWhen(true)] string? domain)
	{
		if (string.IsNullOrEmpty(domain) || domain.Length > 255)
			return false;

		var dots = 0;
		var labelLength = 0;

		for (var i = 0; i < domain.Length; i++)
		{
			var c = domain[i];

			if (c == '.')
			{
				if (labelLength == 0 || domain[i - 1] == '-')
					return false;

				dots++;
				labelLength = 0;
				continue;
			}

			if (c == '-')
			{
				if (labelLength == 0)
					return false;
			}
			else if (!IsAsciiLetterOrDigit(c))
				return false;

			if (++labelLength > 63)
				return false;
		}

		return labelLength > 0 && domain[^1] != '-' && dots > 0;
	}

	/// <summary>
	/// Checks if the value can be safely written into an Authentication-Results header as a property value.
	/// </summary>
	internal static bool IsSafeAuthResultsValue(string? value)
	{
		if (string.IsNullOrEmpty(value) || value.Length > 255)
			return false;

		foreach (var c in value)
		{
			if (!IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_'))
				return false;
		}

		return true;
	}

	private static bool IsValidLocalPart(ReadOnlySpan<char> local)
	{
		if (local.Length == 0)
			return false;

		// Quoted-string
		if (local[0] == '"')
		{
			if (local.Length < 2 || local[^1] != '"')
				return false;

			for (var i = 1; i < local.Length - 1; i++)
			{
				var c = local[i];

				if (c == '\\')
				{
					i++;
					if (i >= local.Length - 1 || local[i] < 32 || local[i] > 126)
						return false;
				}
				else if (c == '"' || c < 32 || c > 126)
					return false;
			}

			return true;
		}

		// Dot-string
		var atomStart = true;
		foreach (var c in local)
		{
			if (c == '.')
			{
				if (atomStart)
					return false;

				atomStart = true;
				continue;
			}

			if (!IsAText(c))
				return false;

			atomStart = false;
		}

		return !atomStart;
	}

	private static bool IsAText(char c) => IsAsciiLetterOrDigit(c) || "!#$%&'*+-/=?^_`{|}~".IndexOf(c) != -1;

	private static bool IsAsciiLetterOrDigit(char c) => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
