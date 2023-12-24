# CSharp-SMTP-Server [![GitHub release](https://flat.badgen.net/github/release/zabszk/CSharp-SMTP-Server)](https://github.com/zabszk/CSharp-SMTP-Server/releases/) [![NuGet](https://flat.badgen.net/nuget/v/CSharp-SMTP-Server/latest)](https://www.nuget.org/packages/CSharp-SMTP-Server/) [![License](https://flat.badgen.net/github/license/zabszk/CSharp-SMTP-Server)](https://github.com/zabszk/CSharp-SMTP-Server/blob/master/LICENSE)
Simple (receive only) SMTP server library for C#.

This server is only returning all received emails to interface provided by the software running this library.

# Supported features
* TLS and STARTTLS
* AUTH LOGIN and AUTH PLAIN

# Compatible with
* RFC 822 (STANDARD FOR THE FORMAT OF ARPA INTERNET TEXT MESSAGES)
* RFC 1869 (SMTP Service Extensions)
* RFC 2554 (SMTP Service Extension for Authentication)
* RFC 3463 (Enhanced Mail System Status Codes)
* RFC 4616 (The PLAIN Simple Authentication and Security Layer (SASL) Mechanism)
* RFC 4954 (SMTP Service Extension for Authentication)
* RFC 5321 (SMTP Protocol)
* RFC 6376 (DomainKeys Identified Mail (DKIM) Signatures)
* RFC 7208 (Sender Policy Framework)
* RFC 7372 (Email Authentication Status Codes)
* RFC 7489 (Domain-based Message Authentication, Reporting, and Conformance (DMARC))
* RFC 8463 (A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM))

# 3rd party services and libraries usage
* This library by default uses Cloudflare Public DNS Servers (1.1.1.1) to perform SPF and DMARC validation. IP address of the DNS server can be changed or both validations can be disabled using ServerOptions class.
* This library by default downloads Public Suffix List managed by Mozilla Foundation from GitHub. The list is licensed under Mozilla Public License v. 2.0. The download URL can be changed in ServerOptions class. The list is NOT downloaded if DnsServerEndpoint is set to null in ServerOptions class.
* This library uses [MimeKit](https://github.com/jstedfast/MimeKit) library created by .NET Foundation and Contributors and licensed under [The MIT License](https://raw.githubusercontent.com/jstedfast/MimeKit/master/LICENSE).

# Basic usage
```cs
var server = new SMTPServer(new[]
{
	new ListeningParameters(IPAddress.IPv6Any, new ushort[]{25, 587}, new ushort[]{465}, true)
}, new ServerOptions(){ServerName = "Test SMTP Server", RequireEncryptionForAuth = false}, new DeliveryInterface(), new LoggerInterface());
//with TLS:
//}, new ServerOptions() { ServerName = "Test SMTP Server", RequireEncryptionForAuth = true}, new DeliveryInterface(), new LoggerInterface(), new X509Certificate2("PathToCertWithKey.pfx"));
		
server.SetAuthLogin(new AuthenticationInterface());
server.SetFilter(new FilterInterface());
server.Start();
```
      
```cs
class LoggerInterface : ILogger
{
	public void LogError(string text) => Console.WriteLine("[LOG] " + text);
}
```
  
```cs
class DeliveryInterface : IMailDelivery
{
	//Let's just print all emails
	public Task EmailReceived(MailTransaction transaction)
	{
		Console.WriteLine(
			$"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo (Commands): {transaction.DeliverTo.Aggregate((current, item) => current + ", " + item)}\nTo (Headers): {transaction.To.Aggregate((current, item) => current + ", " + item)}\nCc: {transaction.Cc.Aggregate((current, item) => current + ", " + item)}\nBcc: {transaction.Bcc.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");
		return Task.CompletedTask;
	}

	//We only own "@smtp.demo" and we don't want any emails to other domains
	public Task<UserExistsCodes> DoesUserExist(string emailAddress) => Task.FromResult(emailAddress.EndsWith("@smtp.demo", StringComparison.OrdinalIgnoreCase)
		? UserExistsCodes.DestinationAddressValid
		: UserExistsCodes.BadDestinationSystemAddress);
}
```

```cs
class AuthenticationInterface : IAuthLogin
{
	//123 is password for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)

	public Task<bool> AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
		EndPoint remoteEndPoint,
		bool secureConnection) => Task.FromResult(password == "123");

	public Task<bool> AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
		Task.FromResult(password == "123");
}
```

```cs
class FilterInterface : IMailFilter
{
	//Allow all connections
	public Task<SmtpResult> IsConnectionAllowed(EndPoint ep) => Task.FromResult(new SmtpResult(SmtpResultType.Success));

	//Let's block .invalid TLD
	public Task<SmtpResult> IsAllowedSender(string source, EndPoint ep) => Task.FromResult(source.TrimEnd().EndsWith(".invalid")
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success));
		
	//Let's reject Softfail as well
	public Task<SmtpResult> IsAllowedSenderSpfVerified(string source, EndPoint? ep, SpfResult spfResult) => Task.FromResult(spfResult == SpfResult.Softfail
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new
			SmtpResult(SmtpResultType.Success));

	//Let's block all emails to root at any domain
	public Task<SmtpResult> CanDeliver(string source, string destination, bool authenticated, string username,
		EndPoint ep) => Task.FromResult(destination.TrimStart().StartsWith("root@", StringComparison.OrdinalIgnoreCase)
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success));

	//Let's blacklist word "spam"
	public Task<SmtpResult> CanProcessTransaction(MailTransaction transaction) => Task.FromResult(transaction.GetMessageBody() != null && transaction.GetMessageBody()!.Contains("spam", StringComparison.OrdinalIgnoreCase)
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success));
}
```

# Generating PFX from PEM keys
You can generate PFX from PEM certificate and PEM private key using openssl:
```
openssl pkcs12 -export -in public.pem -inkey private.pem -out CertWithKey.pfx
```
