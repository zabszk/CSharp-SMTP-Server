using System;
using System.Threading.Tasks;
using MimeKit;
using MimeKit.Cryptography;

namespace CSharp_SMTP_Server.Protocol.DKIM;

/// <summary>
/// DKIM validator
/// </summary>
public class DkimValidator
{
	/// <summary>
	/// DkimVerifier used by this class
	/// </summary>
	// ReSharper disable once MemberCanBePrivate.Global
	public readonly DkimVerifier Verifier;

	/// <summary>
	///Class constructor
	/// </summary>
	/// <param name="keyLocator">DKIM Public Key Locator used for DKIM validation</param>
	/// <param name="minimumRsaKeyLength">Minimum RSA key length</param>
	/// <param name="allowSha1">If false, all SHA1 based signatures are considered invalid</param>
	// ReSharper disable once MemberCanBePrivate.Global
	public DkimValidator(IDkimPublicKeyLocator keyLocator, int minimumRsaKeyLength = 2048, bool allowSha1 = false)
	{
		Verifier = new DkimVerifier(keyLocator)
		{
			MinimumRsaKeyLength = minimumRsaKeyLength
		};

		if (allowSha1)
			Verifier.Enable(DkimSignatureAlgorithm.RsaSha1);
		else Verifier.Disable(DkimSignatureAlgorithm.RsaSha1);
	}

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsClient">DNS client used for DKIM validation</param>
	/// <param name="minimumRsaKeyLength">Minimum RSA key length</param>
	/// <param name="allowSha1">If false, all SHA1 based signatures are considered invalid</param>
	// ReSharper disable once MemberCanBePrivate.Global
	public DkimValidator(DnsClient.DnsClient dnsClient, int minimumRsaKeyLength = 2048, bool allowSha1 = false) : this(new DkimKeyLocator(dnsClient), minimumRsaKeyLength, allowSha1) { }

	internal DkimValidator(SMTPServer server) : this(server.DnsClient!, server.Options.MailAuthenticationOptions.DkimOptions.MinimumKeyLength, server.Options.MailAuthenticationOptions.DkimOptions.AllowSha1) { }

	/// <summary>
	/// Validates Mail Transaction using DMARC
	/// </summary>
	/// <param name="transaction">Transaction to validate</param>
	/// <returns>Validation result</returns>
	/// <exception cref="Exception">Returned if DMARC Validator was never initialized.</exception>
	public async Task<DkimValidationResult> ValidateTransaction(MailTransaction transaction)
	{
		try
		{
			var headerIndex = transaction.ParsedMessage.Headers.IndexOf(HeaderId.DkimSignature);

			if (headerIndex == -1)
				return DkimValidationResult.None;

			return await Verifier.VerifyAsync(FormatOptions.Default, transaction.ParsedMessage, transaction.ParsedMessage.Headers[headerIndex]);
		}
		catch
		{
			return DkimValidationResult.Temperror;
		}
	}

	/// <summary>
	/// DKIM validation result
	/// </summary>
	public readonly struct DkimValidationResult
	{
		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="validationResult">Validation result</param>
		/// <param name="selector">Selector used for signing</param>
		/// <param name="domain">Domain used for signing</param>
		/// <param name="rsaKeySize">RSA Key Length, 0 if RSA wasn't used</param>
		/// <param name="dkimSignatureAlgorithm">Signature algorithm used for signing</param>
		public DkimValidationResult(ValidationResult validationResult, string? selector = null, string? domain = null, int rsaKeySize = 0, DkimSignatureAlgorithm dkimSignatureAlgorithm = DkimSignatureAlgorithm.RsaSha256)
		{
			ValidationResult = validationResult;
			Selector = selector;
			Domain = domain;
			RsaKeySize = rsaKeySize;
			SignatureAlgorithm = dkimSignatureAlgorithm;
		}

		internal static DkimValidationResult None => new(ValidationResult.None);

		internal static DkimValidationResult Temperror => new(ValidationResult.Temperror);

		/// <summary>
		/// Validation result
		/// </summary>
		public readonly ValidationResult ValidationResult;

		/// <summary>
		/// Selector used for signing
		/// </summary>
		public readonly string? Selector;

		/// <summary>
		/// Domain used for signing
		/// </summary>
		public readonly string? Domain;

		/// <summary>
		/// RSA Key Length, 0 if RSA wasn't used
		/// </summary>
		public readonly int RsaKeySize;

		/// <summary>
		/// Signature algorithm used for signing
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		public readonly DkimSignatureAlgorithm SignatureAlgorithm;

		/// <summary>
		/// Generates "header.a=" value of "Authentication-Results" for this DKIM validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		public string SignatureAlgorithmHeader
		{
			get
			{
				if (ValidationResult != ValidationResult.Permerror && ValidationResult != ValidationResult.Fail)
					return string.Empty;

				return SignatureAlgorithm switch
				{
					DkimSignatureAlgorithm.RsaSha1 => " header.a=rsa-sha1",
					DkimSignatureAlgorithm.RsaSha256 => " header.a=rsa-sha256",
					DkimSignatureAlgorithm.Ed25519Sha256 => " header.a=ed25519-sha256",
					_ => " header.a=unknown"
				};
			}
		}
	}
}