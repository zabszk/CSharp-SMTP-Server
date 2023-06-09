using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol;
using CSharp_SMTP_Server.Protocol.Commands;
using CSharp_SMTP_Server.Protocol.Responses;

namespace CSharp_SMTP_Server.Networking
{
	internal class ClientProcessor : IDisposable
	{
		internal ClientProcessor(TcpClient c, Listener l, bool secure)
		{
			_t = _ts.Token;
			_listener = l;
			_client = c;
			_innerStream = c.GetStream();
			_stream = _innerStream;
			_encoder = new UTF8Encoding();
			if (_client.Client.RemoteEndPoint is IPEndPoint ipe)
				RemoteEndPoint = ipe;
			Encryption = ConnectionEncryption.Plaintext;
			Secure = secure && Server.Certificate != null;

			if (Server.SpfValidator != null)
				SpfResultsCache = new();

			Init();
		}

		internal readonly Dictionary<string, ValidationResult>? SpfResultsCache;

		private readonly CancellationTokenSource _ts = new();
		private readonly CancellationToken _t;

		internal readonly IPEndPoint? RemoteEndPoint;

		private readonly TcpClient _client;
		private readonly NetworkStream _innerStream;
		private Stream _stream;
		private StreamReader? _reader;
		private readonly Listener _listener;
		private readonly UTF8Encoding _encoder;
		private bool _greetSent;
		private int _fails;

		internal MailTransaction? Transaction;
		internal StringBuilder? DataBuilder;
		internal ulong Counter;

		internal bool Secure { get; private set; }
		internal ConnectionEncryption Encryption { get; private set; }
		internal ushort CaptureData;
		internal string? Username, TempUsername;
		private ushort _protocolVersion;
		private bool _dispose;

		private async void Init()
		{
			if (Secure)
			{
				Encryption = ConnectionEncryption.Tls;
				_stream = new SslStream(_innerStream, false);
				await ((SslStream)_stream).AuthenticateAsServerAsync(Server.Certificate!, false, Server.Options.Protocols, true);
			}
			else
				await Greet();

			if (!_dispose)
				_reader = new StreamReader(_stream);

			_ = Receive();
		}

		private async Task Greet()
		{
			if (Server.Filter != null)
			{
				var filterResult = await Server.Filter.IsConnectionAllowed(RemoteEndPoint);

				if (filterResult.Type != SmtpResultType.Success)
				{
					await WriteCode(550,
						filterResult.Type == SmtpResultType.PermanentFail ? "5.7.1" : "4.7.1",
						string.IsNullOrWhiteSpace(filterResult.FailMessage)
							? "Delivery not authorized, connection refused"
							: filterResult.FailMessage);

					Dispose();
					return;
				}
			}

			_greetSent = true;
			await WriteText($"220 {Server.Options.ServerName} ESMTP");
		}

		private async Task Receive()
		{
			if (Secure)
			{
				while (!_t.IsCancellationRequested && !((SslStream)_stream).IsAuthenticated)
					await Task.Delay(5, _t);

				if (!_greetSent)
					await Greet();
			}

			if (!_greetSent)
				return;

			while (!_t.IsCancellationRequested && !_reader!.EndOfStream && _client.Connected && _stream.CanRead)
			{
				try
				{
					var read = await _reader.ReadLineAsync();

					if (read == null)
						continue;

					await ProcessResponse(read);
				}
				catch (ObjectDisposedException)
				{
					break;
				}
				catch (Exception e)
				{
					Server.LoggerInterface?.LogError("[Client receive loop] Exception: " + e.GetType().FullName + ", " + e.Message);

					_fails++;

					if (_fails <= 3) continue;
					break;
				}
			}

			if (!_dispose)
				Dispose();
		}

		internal async Task WriteText(string text)
		{
			try
			{
				if (!_stream.CanWrite) return;
				var encoded = _encoder.GetBytes(text + "\r\n");
				await _stream.WriteAsync(encoded);
			}
			catch (Exception e)
			{
				Server.LoggerInterface?.LogError("[Client write] Exception: " + e.Message);

				_fails++;
				if (_fails > 3) Dispose();
			}
		}

		internal async Task WriteCode(ushort code) => await SMTPCodes.SendCode(this, code);
		internal async Task WriteCode(ushort code, string enhanced) => await SMTPCodes.SendCode(this, code, enhanced);
		internal async Task WriteCode(ushort code, string enhanced, string text) => await SMTPCodes.SendCode(this, code, enhanced, text);

		internal SMTPServer Server => _listener.Server;

		private async Task ProcessResponse(string response)
		{
			if (!_greetSent)
				return;

			switch (CaptureData)
			{
				case 1:
					await TransactionCommands.ProcessData(this, response);
					return;

				case 2:
				case 3:
				case 4:
					await AuthenticationCommands.ProcessData(this, response.Trim());
					return;
			}

			response = response.Trim();

			string command;
			var data = string.Empty;

			if (response.Contains(':', StringComparison.Ordinal)) command = response[..response.IndexOf(":", StringComparison.Ordinal)].ToUpperInvariant().TrimEnd();
			else if (response.Contains(' ', StringComparison.Ordinal))
				command = response[..response.IndexOf(" ", StringComparison.Ordinal)].ToUpper(CultureInfo.InvariantCulture).TrimEnd();
			else command = response.ToUpperInvariant();

			if (command.Length != response.Length)
				data = response[command.Length..].TrimStart();

			switch (command.Trim())
			{
				case "EHLO":
					Transaction = null;
					_protocolVersion = 2;
					await WriteText($"250-{Server.Options.ServerName} at your service");
					if (Server.AuthLogin != null) await WriteText("250-AUTH LOGIN PLAIN");
					if (!Secure && Server.Certificate != null) await WriteText("250-STARTTLS");
					await WriteText("250 8BITMIME");
					break;

				case "HELO":
					Transaction = null;
					_protocolVersion = 1;
					await WriteText($"250 {Server.Options.ServerName} at your service");
					break;

				case "STARTTLS":
					if (Secure)
					{
						await WriteCode(503, "5.5.1");
						return;
					}

					if (Server.Certificate == null)
					{
						await WriteCode(502, "5.5.1");
						return;
					}

					await WriteCode(220, "2.0.0", "Ready for TLS");

					_stream = new SslStream(_innerStream, false);
					Secure = true;
					Encryption = ConnectionEncryption.StartTls;
					await ((SslStream)_stream).AuthenticateAsServerAsync(Server.Certificate, false, Server.Options.Protocols, true);
					_reader = new StreamReader(_stream);
					break;

				case "HELP":
					await WriteCode(214, "2.0.0");
					break;

				case "AUTH":
					if (_protocolVersion == 0)
					{
						await WriteCode(503, "5.5.1", "EHLO/HELO first.");
						return;
					}
					await AuthenticationCommands.ProcessCommand(this, data);
					break;

				case "NOOP":
					await WriteCode(250, "2.0.0");
					break;

				case "QUIT":
					await WriteCode(221, "2.0.0");
					Dispose();
					break;

				case "RSET":
				case "MAIL FROM":
				case "RCPT TO":
				case "DATA":
					if (_protocolVersion == 0)
					{
						await WriteCode(503, "5.5.1", "EHLO/HELO first.");
						return;
					}
					await TransactionCommands.ProcessCommand(this, command, data);
					break;

				case "VRFY":
					if (_protocolVersion == 0)
					{
						await WriteCode(503, "5.5.1", "EHLO/HELO first.");
						return;
					}
					await WriteCode(252, "5.5.1");
					break;

				default:
					if (_protocolVersion == 0)
					{
						await WriteCode(503, "5.5.1", "EHLO/HELO first.");
						return;
					}
					await WriteCode(502, "5.5.1");
					break;
			}
		}

		public void Dispose()
		{
			if (_dispose) return;
			_dispose = true;

			_ts.Cancel();

			Transaction = null;

			_reader?.Close();
			_reader?.Dispose();

			_stream.Close();
			_stream.Dispose();

			_innerStream.Close();
			_innerStream.Dispose();

			_client.Close();
			_client.Dispose();

			if (_listener.ClientProcessors.Contains(this))
				_listener.ClientProcessors.Remove(this);
		}
	}
}