using System;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp;

internal class LoggerInterface : ILogger
{
	public void LogError(string text) => Console.WriteLine($"[ERROR] {text}" );

	public void LogInfo(string text) => Console.WriteLine($"[INFO ] {text}");

	public void LogVerbose(string text) => Console.WriteLine($"[VERB ] {text}");

}