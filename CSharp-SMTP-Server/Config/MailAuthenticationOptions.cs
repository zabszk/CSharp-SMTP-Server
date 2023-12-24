using System.Diagnostics.CodeAnalysis;

namespace CSharp_SMTP_Server.Config;

/// <summary>
/// Email authentication options
/// </summary>
public class MailAuthenticationOptions
{
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="spfOptions">Options of SPF mail authentication</param>
	/// <param name="dkimOptions">Options of DKIM mail authentication</param>
	/// <param name="dmarcOptions">Options of DMARC mail authentication</param>
	public MailAuthenticationOptions(SpfOptions? spfOptions = null, DkimOptions? dkimOptions = null, DmarcOptions? dmarcOptions = null)
	{
		SpfOptions = spfOptions ?? new();
		DkimOptions = dkimOptions ?? new();
		DmarcOptions = dmarcOptions ?? new();
	}

	/// <summary>
	/// Configuration of SPF validation (applies ONLY to emails sent by unauthenticated users).
	/// </summary>
	public readonly SpfOptions SpfOptions;

	/// <summary>
	/// Enables or disables DKIM validation of emails sent by unauthenticated users.
	/// </summary>
	public readonly DkimOptions DkimOptions;

	/// <summary>
	/// Rejects emails from domains that didn't pass both SPF and DKIM configured.
	/// </summary>
	// ReSharper disable once FieldCanBeMadeReadOnly.Global
	public bool RejectUnauthenticatedEmails = false;

	/// <summary>
	/// Enables or disables DMARC validation of emails sent by unauthenticated users.
	/// </summary>
	public readonly DmarcOptions DmarcOptions;

	/// <summary>
	/// If enabled, the Public Suffix List is downloaded (by default from 3rd PARTY SERVICE!) on server startup.
	/// You can change the address by changing <see cref="PublicSuffixListUrl"/> variable (eg. to a server hosted by yourself).
	/// If you want, you can disable this feature and don't use DMARC or manually load the list before starting the server.
	/// </summary>
	// ReSharper disable once FieldCanBeMadeReadOnly.Global
	// ReSharper disable once ConvertToConstant.Global
	public bool AutomaticallyDownloadPublicSuffixList = true;

	/// <summary>
	/// URL of list of all public suffixes of domains
	/// </summary>
	// ReSharper disable once FieldCanBeMadeReadOnly.Global
	// ReSharper disable once ConvertToConstant.Global
	public string PublicSuffixListUrl = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat";

	internal bool AnyMechanismEnabled => SpfOptions.ValidateSpf || DkimOptions.ValidateDkim || DmarcOptions.ValidateDmarc;
}

/// <summary>
/// SPF validation options
/// </summary>
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "ConvertToConstant.Global")]
public class SpfOptions
{
	/// <summary>
	/// Default constructor
	/// </summary>
	/// <param name="validateSpf">Indicates whether SPF validation should be enabled</param>
	public SpfOptions(bool validateSpf = true)
	{
		ValidateSpf = validateSpf;
	}

	/// <summary>
	/// Enables or disables SPF validation of emails sent by unauthenticated users.
	/// </summary>
	public readonly bool ValidateSpf;

	/// <summary>
	/// If enabled, emails that didn't pass SPF validation with "Fail" result will be rejected.
	/// </summary>
	public bool RejectSpfFail = true;

	/// <summary>
	/// If enabled, emails that didn't pass SPF validation with "Softfail" result will be rejected.
	/// </summary>
	public bool RejectSpfSoftfail = true;

	/// <summary>
	/// If enabled, emails that passed DKIM validation will be delivered regardless of SPF validation "Fail" result.
	/// </summary>
	public bool DkimPassOverridesSpfFail = true;

	/// <summary>
	/// If enabled, emails that passed DKIM validation will be delivered regardless of SPF validation "Softfail" result.
	/// </summary>
	public bool DkimPassOverridesSpfSoftfail = true;

	/// <summary>
	/// If enabled, address provided in HELO or EHLO command is authenticated using SPF.
	/// </summary>
	public bool AuthenticateEhloAddress = true;
}

/// <summary>
/// SPF validation options
/// </summary>
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "ConvertToConstant.Global")]
public class DkimOptions
{
	/// <summary>
	/// Default constructor
	/// </summary>
	/// <param name="validateDkim">Indicates whether DKIM validation should be enabled</param>
	public DkimOptions(bool validateDkim = true)
	{
		ValidateDkim = validateDkim;
	}

	/// <summary>
	/// Enables or disables DKIM validation of emails sent by unauthenticated users.
	/// </summary>
	public readonly bool ValidateDkim;

	/// <summary>
	/// Minimum RSA key length.
	/// </summary>
	public int MinimumKeyLength = 2048;

	/// <summary>
	/// If false, all SHA1 based signatures are considered invalid.
	/// </summary>
	public bool AllowSha1 = false;
}

/// <summary>
/// DMARC validation options
/// </summary>
[SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Global")]
[SuppressMessage("ReSharper", "ConvertToConstant.Global")]
public class DmarcOptions
{
	/// <summary>
	/// Default constructor
	/// </summary>
	/// <param name="validateDmarc">Indicates whether SPF validation should be enabled</param>
	public DmarcOptions(bool validateDmarc = true)
	{
		ValidateDmarc = validateDmarc;
	}

	/// <summary>
	/// Enables or disables DMARC validation of emails sent by unauthenticated users.
	/// </summary>
	public readonly bool ValidateDmarc;

	/// <summary>
	/// If enabled, emails that didn't pass DMARC validation with "Reject" result will be rejected.
	/// </summary>
	public bool RejectDmarcReject = true;

	/// <summary>
	/// If enabled, emails that didn't pass DMARC validation with "Quarantine" result will be rejected.
	/// </summary>
	public bool RejectDmarcQuarantine = true;
}