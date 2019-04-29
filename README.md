# CSharp-SMTP-Server
Simple (receive only) SMTP server library for C#, written in .NET Standard.

This server is only returning all received emails to interface provided by the software running this library.

# Supported features
* TLS and STARTTLS
* AUTH LOGIN and AUTH PLAIN

# Compatible with
* RFC 1869 (SMTP Service Extensions)
* RFC 2254 (SMTP Service Extension for Authentication)
* RFC 3463 (Enhanced Mail System Status Codes)
* RFC 5321 (SMTP Protocol)

# Basic usage
```cs
var server = new SMTPServer(new[]
{
	new ListeningParameters()
	{
		IpAddress = IPAddress.Any,
		RegularPorts = new ushort[] {25, 587},
		TlsPorts = new ushort[] {465}
	},
	new ListeningParameters()
	{
		IpAddress = IPAddress.IPv6Any,
		RegularPorts = new ushort[] {25, 587},
		TlsPorts = new ushort[] {465}
	}
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
	public void EmailReceived(MailTransaction transaction) => Console.WriteLine(
		$"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo: {transaction.To.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");

	//We only own "@smtp.demo" and we don't want any emails to other domains
	public UserExistsCodes DoesUserExist(string emailAddress) => emailAddress.EndsWith("@smtp.demo")
		? UserExistsCodes.DestinationAddressValid
		: UserExistsCodes.BadDestinationSystemAddress;
}
```

```cs
class AuthenticationInterface : IAuthLogin
{
	//123 is password for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)

	public bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
		EndPoint remoteEndPoint,
		bool secureConnection) => password == "123";

	public bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
		password == "123";
}
```

```cs
class FilterInterface : IMailFilter
{
	//Allow all connections
	public SmtpResult IsConnectionAllowed(EndPoint ep) => new SmtpResult(SmtpResultType.Success);

	//Let's block .invalid TLD. You can do here eg. SPF validation
	public SmtpResult IsAllowedSender(string source, EndPoint ep) => source.TrimEnd().EndsWith(".invalid")
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success);

	//Let's block all emails to root at any domain
	public SmtpResult CanDeliver(string source, string destination, bool authenticated, string username,
		EndPoint ep) => destination.TrimStart().StartsWith("root@")
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success);

	//Let's blacklist word "spam"
	public SmtpResult CanProcessTransaction(MailTransaction transaction) => transaction.Body.ToLower().Contains("spam")
		? new SmtpResult(SmtpResultType.PermanentFail)
		: new SmtpResult(SmtpResultType.Success);
}
```

# Generating PFX from PEM keys
You can generate PFX from PEM certificate and PEM private key using openssl:
```
openssl pkcs12 -export -in public.pem -inkey private.pem -out CertWithKey.pfx
```
