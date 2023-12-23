using System;
using System.Threading.Tasks;
using MimeKit;
using MimeKit.Cryptography;

namespace CSharp_SMTP_Server.Protocol.DKIM;

/// <summary>
/// DKIM validator
/// </summary>
public class DkimValidator : IMailValidator
{
	private readonly DkimVerifier _verifier;

	/// <summary>
	///Class constructor
	/// </summary>
	/// <param name="keyLocator">DKIM Public Key Locator used for DKIM validation</param>
	// ReSharper disable once MemberCanBePrivate.Global
	public DkimValidator(IDkimPublicKeyLocator keyLocator)
	{
		_verifier = new DkimVerifier(keyLocator);
	}

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsClient">DNS client used for DKIM validation</param>
	public DkimValidator(DnsClient.DnsClient dnsClient) : this(new DkimKeyLocator(dnsClient)){ }

	/// <summary>
	/// Validates Mail Transaction using DMARC
	/// </summary>
	/// <param name="transaction">Transaction to validate</param>
	/// <returns>Validation result</returns>
	/// <exception cref="Exception">Returned if DMARC Validator was never initialized.</exception>
	public async Task<ValidationResult> ValidateTransaction(MailTransaction transaction)
	{
		try
		{
			var headerIndex = transaction.ParsedMessage.Headers.IndexOf(HeaderId.DkimSignature);

			if (headerIndex == -1)
				return ValidationResult.None;

			return (await _verifier.VerifyAsync(transaction.ParsedMessage, transaction.ParsedMessage.Headers[headerIndex])) ? ValidationResult.Pass : ValidationResult.Fail;
		}
		catch
		{
			return ValidationResult.Temperror;
		}
	}
}