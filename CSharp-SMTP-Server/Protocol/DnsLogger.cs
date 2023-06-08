using System;
using DnsClient.Logging;

namespace CSharp_SMTP_Server.Protocol;

/// <summary>
/// DNS client errors logging class
/// </summary>
public class DnsLogger : IErrorLogging
{
	private readonly SMTPServer _server;

	/// <summary>
	/// Class constructor
	/// </summary>
	/// <param name="server">SMTP server</param>
	public DnsLogger(SMTPServer server) => _server = server;

	/// <summary>
	/// Logs DNS client error
	/// </summary>
	/// <param name="message">Error message to log</param>
	public void LogError(string message) => _server.LoggerInterface?.LogError($"[DNS ERROR] {message}");

	/// <summary>
	/// Logs DNS client error
	/// </summary>
	/// <param name="message">Error message to log</param>
	/// <param name="e">Exception to log</param>
	public void LogException(string message, Exception e) => _server.LoggerInterface?.LogError($"[DNS ERROR] {message}. Exception: {e.GetType()} - {e.Message}{Environment.NewLine}{e.StackTrace}");
}