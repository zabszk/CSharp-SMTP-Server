using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DnsClient.Data.Records;
using DnsClient.Enums;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;

namespace CSharp_SMTP_Server.Protocol.DKIM;

/// <summary>
/// DKIM key locator (from DNS)
/// </summary>
public class DkimKeyLocator : DkimPublicKeyLocatorBase
{
	/// <summary>
	/// DNS Client used to validate SPF records
	/// </summary>
	private readonly DnsClient.DnsClient _dnsClient;

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="dnsClient">DNS client used for SPF validation</param>
	public DkimKeyLocator(DnsClient.DnsClient dnsClient) => _dnsClient = dnsClient;

	/// <inheritdoc />
	public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = new())
	{
		var query = _dnsClient.Query($"{selector}._domainkey.{domain}", QType.TXT);
		query.Wait(cancellationToken);

		if (cancellationToken.IsCancellationRequested || query.Result.ErrorCode != DnsErrorCode.NoError || query.Result.Records == null)
			return GetPublicKey(string.Empty);

		var builder = new StringBuilder();

		foreach (var record in query.Result.Records)
			if (record is DnsRecord.TXTRecord txtRecord)
				builder.Append(txtRecord.Text);

		return GetPublicKey(builder.ToString());
	}

	/// <inheritdoc />
	public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = new())
	{
		return Task.Run (() => LocatePublicKey (methods, domain, selector, cancellationToken), cancellationToken);
	}
}