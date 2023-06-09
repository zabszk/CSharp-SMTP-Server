using System;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp;

internal class LoggerInterface : ILogger
{
	public void LogError(string text) => Console.WriteLine("[LOG] " + text);
}