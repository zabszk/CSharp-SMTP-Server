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

server.SetAuthLogin(new AuthenticationInterface());
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
  public void EmailReceived(MailTransaction transaction) => Console.WriteLine(
  $"\n\n--- EMAIL TRANSACTION ---\nSource IP: {transaction.RemoteEndPoint}\nAuthenticated: {transaction.AuthenticatedUser ?? "(not authenticated)"}\nFrom: {transaction.From}\nTo: {transaction.To.Aggregate((current, item) => current + ", " + item)}\nBody: {transaction.Body}\n--- END OF TRANSACTION ---\n\n");

  public bool UserExists(string emailAddress) => true;
}
```

```cs
class AuthenticationInterface : IAuthLogin
{
  public bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
    EndPoint remoteEndPoint,
    bool secureConnection) => password == "123";

  public bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
    password == "123";
}
```
