using System;
using DnsClient.Logging;

namespace CSharp_SMTP_Server.Protocol.SPF;

internal class DnsLogger : IErrorLogging
{
	private readonly SMTPServer _server;

	internal DnsLogger(SMTPServer server) => _server = server;

	public void LogError(string message) => _server.LoggerInterface?.LogError($"[DNS ERROR (FOR SPF)] {message}");

	public void LogException(string message, Exception e) => _server.LoggerInterface?.LogError($"[DNS ERROR (FOR SPF)] {message}. Exception: {e.GetType()} - {e.Message}{Environment.NewLine}{e.StackTrace}");
}