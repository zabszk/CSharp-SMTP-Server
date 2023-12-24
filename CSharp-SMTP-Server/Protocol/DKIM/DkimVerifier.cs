using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace CSharp_SMTP_Server.Protocol.DKIM;

/// <summary>
/// Modified version of MimeKit DkimVerifier class.
/// Original code is licensed under The MIT License. Details can be found in README.md in this repository.
/// </summary>
public class DkimVerifier : DkimVerifierBase
{
	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="publicKeyLocator">Public Key Locator</param>
	public DkimVerifier(IDkimPublicKeyLocator publicKeyLocator) : base(publicKeyLocator)
	{

	}

	/// <summary>
	/// Validates DKIM signature
	/// </summary>
	/// <param name="options">Validation option</param>
	/// <param name="message">Message to validate</param>
	/// <param name="dkimSignature">DKIM signature to validate</param>
	/// <returns></returns>
	public async Task<DkimValidator.DkimValidationResult> VerifyAsync(FormatOptions options, MimeMessage message, Header dkimSignature)
	{
		if (dkimSignature.Id != HeaderId.DkimSignature)
			return DkimValidator.DkimValidationResult.None;
			//throw new ArgumentException("The signature parameter MUST be a DKIM-Signature header.", nameof(dkimSignature));

		var parameters = ParseParameterTags(/*dkimSignature.Id,*/ dkimSignature.Value);

		if (parameters == null)
			return DkimValidator.DkimValidationResult.None;

		AsymmetricKeyParameter key;

		if (!ValidateDkimSignatureParameters(parameters, out DkimSignatureAlgorithm signatureAlgorithm, out DkimCanonicalizationAlgorithm headerAlgorithm, out DkimCanonicalizationAlgorithm bodyAlgorithm,
			    out string d, out string s, out string q, out string[] headers, out string bh, out string b, out int maxLength))
			return DkimValidator.DkimValidationResult.None;

		if (!IsEnabled(signatureAlgorithm))
			return DkimValidator.DkimValidationResult.None;

		options = options.Clone();
		options.NewLineFormat = NewLineFormat.Dos;

		// first check the body hash (if that's invalid, then the entire signature is invalid)
		if (!VerifyBodyHash(options, message, signatureAlgorithm, bodyAlgorithm, maxLength, bh))
			return DkimValidator.DkimValidationResult.None;

		key = await this.PublicKeyLocator.LocatePublicKeyAsync(q, d, s).ConfigureAwait(false);
		int keyLength = 0;

		if ((key is RsaKeyParameters rsa))
		{
			if (rsa.Modulus.BitLength < this.MinimumRsaKeyLength)
				return DkimValidator.DkimValidationResult.None;

			keyLength = rsa.Modulus.BitLength;
		}

		return new DkimValidator.DkimValidationResult(VerifySignature(options, message, dkimSignature, signatureAlgorithm, key, headers, headerAlgorithm, b) ? ValidationResult.Pass : ValidationResult.Fail, s, d, keyLength);
	}

	private static bool ValidateDkimSignatureParameters(IDictionary<string, string> parameters, out DkimSignatureAlgorithm algorithm, out DkimCanonicalizationAlgorithm headerAlgorithm,
		out DkimCanonicalizationAlgorithm bodyAlgorithm, out string d, out string s, out string q, out string[] headers, out string bh, out string b, out int maxLength)
	{
		bool containsFrom = false;

		algorithm = default;
		headerAlgorithm = default;
		bodyAlgorithm = default;
		d = s = q = bh = b = string.Empty;
		headers = null!;
		maxLength = 0;

		if (!parameters.TryGetValue("v", out string v))
			return false;
			//throw new FormatException("Malformed DKIM-Signature header: no version parameter detected.");

		if (v != "1")
			return false;
			//throw new FormatException(string.Format("Unrecognized DKIM-Signature version: v={0}", v));

		if (!ValidateCommonSignatureParameters(/*"DKIM-Signature",*/ parameters, out algorithm, out headerAlgorithm, out bodyAlgorithm, out d, out s, out q, out headers, out bh, out b, out maxLength))
			return false;

		for (int i = 0; i < headers.Length; i++)
		{
			if (headers[i].Equals("from", StringComparison.OrdinalIgnoreCase))
			{
				containsFrom = true;
				break;
			}
		}

		if (!containsFrom)
			return false;
			//throw new FormatException("Malformed DKIM-Signature header: From header not signed.");

		if (parameters.TryGetValue("i", out string id))
		{
			int at;

			if ((at = id.LastIndexOf('@')) == -1)
				return false;
				//throw new FormatException("Malformed DKIM-Signature header: no @ in the AUID value.");

			var ident = id.AsSpan(at + 1);

			if (!ident.Equals(d.AsSpan(), StringComparison.OrdinalIgnoreCase) && !ident.EndsWith(("." + d).AsSpan(), StringComparison.OrdinalIgnoreCase))
				return false;
				//throw new FormatException("Invalid DKIM-Signature header: the domain in the AUID does not match the domain parameter.");
		}

		return true;
	}

	private static bool ValidateCommonSignatureParameters(/*string header,*/ IDictionary<string, string> parameters, out DkimSignatureAlgorithm algorithm, out DkimCanonicalizationAlgorithm headerAlgorithm,
		out DkimCanonicalizationAlgorithm bodyAlgorithm, out string d, out string s, out string q, out string[] headers, out string bh, out string b, out int maxLength)
	{
		bh = string.Empty;
		headerAlgorithm = default;
		bodyAlgorithm = default;
		headers = null!;
		maxLength = 0;

		if (!ValidateCommonParameters(/*header,*/ parameters, out algorithm, out d, out s, out q, out b))
			return false;

		if (parameters.TryGetValue("l", out string l))
		{
			if (!int.TryParse(l, NumberStyles.None, CultureInfo.InvariantCulture, out maxLength) || maxLength < 0)
				return false;
				//throw new FormatException(string.Format("Malformed {0} header: invalid length parameter: l={1}", header, l));
		}
		else
		{
			maxLength = -1;
		}

		if (parameters.TryGetValue("c", out string c))
		{
			var tokens = c.ToLowerInvariant().Split('/');

			if (tokens.Length == 0 || tokens.Length > 2)
				return false;
				//throw new FormatException(string.Format("Malformed {0} header: invalid canonicalization parameter: c={1}", header, c));

			switch (tokens[0])
			{
				case "relaxed":
					headerAlgorithm = DkimCanonicalizationAlgorithm.Relaxed;
					break;
				case "simple":
					headerAlgorithm = DkimCanonicalizationAlgorithm.Simple;
					break;

				default: return false;
				//default: throw new FormatException(string.Format("Malformed {0} header: invalid canonicalization parameter: c={1}", header, c));
			}

			if (tokens.Length == 2)
			{
				switch (tokens[1])
				{
					case "relaxed":
						bodyAlgorithm = DkimCanonicalizationAlgorithm.Relaxed;
						break;
					case "simple":
						bodyAlgorithm = DkimCanonicalizationAlgorithm.Simple;
						break;

					default: return false;
					//default: throw new FormatException(string.Format("Malformed {0} header: invalid canonicalization parameter: c={1}", header, c));
				}
			}
			else
			{
				bodyAlgorithm = DkimCanonicalizationAlgorithm.Simple;
			}
		}
		else
		{
			headerAlgorithm = DkimCanonicalizationAlgorithm.Simple;
			bodyAlgorithm = DkimCanonicalizationAlgorithm.Simple;
		}

		if (!parameters.TryGetValue("h", out string h))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no signed header parameter detected.", header));

		headers = h.Split(':');

		if (!parameters.TryGetValue("bh", out bh))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no body hash parameter detected.", header));

		return true;
	}

	private static bool ValidateCommonParameters(/*string header,*/ IDictionary<string, string> parameters, out DkimSignatureAlgorithm algorithm,
		out string d, out string s, out string q, out string b)
	{
		d = s = q = b = string.Empty;
		algorithm = default;

		if (!parameters.TryGetValue("a", out string a))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no signature algorithm parameter detected.", header));

		switch (a.ToLowerInvariant())
		{
			case "ed25519-sha256":
				algorithm = DkimSignatureAlgorithm.Ed25519Sha256;
				break;
			case "rsa-sha256":
				algorithm = DkimSignatureAlgorithm.RsaSha256;
				break;
			case "rsa-sha1":
				algorithm = DkimSignatureAlgorithm.RsaSha1;
				break;

			default: return false;
			//default: throw new FormatException(string.Format("Unrecognized {0} algorithm parameter: a={1}", header, a));
		}

		if (!parameters.TryGetValue("d", out d))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no domain parameter detected.", header));

		if (d.Length == 0)
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: empty domain parameter detected.", header));

		if (!parameters.TryGetValue("s", out s))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no selector parameter detected.", header));

		if (s.Length == 0)
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: empty selector parameter detected.", header));

		if (!parameters.TryGetValue("q", out q))
			q = "dns/txt";

		if (!parameters.TryGetValue("b", out b))
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: no signature parameter detected.", header));

		if (b.Length == 0)
			return false;
			//throw new FormatException(string.Format("Malformed {0} header: empty signature parameter detected.", header));

		if (parameters.TryGetValue("t", out string t))
		{
			if (!int.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out int timestamp) || timestamp < 0)
				return false;
				//throw new FormatException(string.Format("Malformed {0} header: invalid timestamp parameter: t={1}.", header, t));
		}

		return true;
	}

	private static Dictionary<string, string>? ParseParameterTags(/*HeaderId header,*/ string signature)
	{
		var parameters = new Dictionary<string, string>();
		var value = new StringBuilder();
		int index = 0;

		while (index < signature.Length)
		{
			while (index < signature.Length && IsWhiteSpace(signature[index]))
				index++;

			if (index >= signature.Length)
				break;

			if (signature[index] == ';' || !IsAlpha(signature[index]))
				return null;
				//throw new FormatException(string.Format("Malformed {0} value.", header.ToHeaderName()));

			int startIndex = index++;

			while (index < signature.Length && signature[index] != '=')
				index++;

			if (index >= signature.Length)
				continue;

			var name = signature.AsSpan(startIndex, index - startIndex).TrimEnd().ToString();

			// skip over '=' and clear value buffer
			value.Length = 0;
			index++;

			while (index < signature.Length && signature[index] != ';')
			{
				if (!IsWhiteSpace(signature[index]))
					value.Append(signature[index]);
				index++;
			}

			if (parameters.ContainsKey(name))
				return null;
				//throw new FormatException(string.Format("Malformed {0} value: duplicate parameter '{1}'.", header.ToHeaderName(), name));

			parameters.Add(name, value.ToString());

			// skip over ';'
			index++;
		}

		return parameters;
	}

	//Code from MimeKit with my modifications.
	private static bool IsAlpha (char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z';

	//Code from MimeKit with my modifications.
	private static bool IsWhiteSpace (char c) => c is ' ' or '\t';
}