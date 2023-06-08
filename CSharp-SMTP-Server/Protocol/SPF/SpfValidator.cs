using System.Net;
using DnsClient;

namespace CSharp_SMTP_Server.Protocol.SPF;

internal class SpfValidator
{
	private readonly DnsClient.DnsClient _dnsClient;
	private readonly SMTPServer _server;

	internal SpfValidator(SMTPServer server)
	{
		_server = server;
		_dnsClient = new DnsClient.DnsClient(_server.Options.DnsServerEndpoint, new DnsClientOptions {ErrorLogging = new DnsLogger(server)});
	}

	internal SpfResult CheckHost(IPAddress ipAddress, string domain)
	{
		return SpfResult.None;
	}
}