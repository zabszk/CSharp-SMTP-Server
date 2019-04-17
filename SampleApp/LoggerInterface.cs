using System;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp
{
	class LoggerInterface : ILogger
	{
		public void LogError(string text) => Console.WriteLine("[LOG] " + text);
	}
}
