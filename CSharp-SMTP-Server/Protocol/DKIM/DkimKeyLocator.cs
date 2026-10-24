using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Misc;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;

namespace CSharp_SMTP_Server.Protocol.DKIM;

/// <summary>
/// DKIM key locator (from DNS)
/// </summary>
public class DkimKeyLocator : DkimPublicKeyLocatorBase
{
	/// <inheritdoc />
	public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = new())
	{
		var query = DnsLookup.QueryTxtRecordWithPrefixAsync($"{selector}._domainkey.{domain}", "v=DKIM1;", cancellationToken);
		query.Wait(cancellationToken);

		return query.Result == null ? throw new Exception ("DKIM record not found in DNS.") : GetPublicKey(query.Result);
	}

	/// <inheritdoc />
	public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = new())
	{
		return Task.Run (() => LocatePublicKey (methods, domain, selector, cancellationToken), cancellationToken);
	}
}