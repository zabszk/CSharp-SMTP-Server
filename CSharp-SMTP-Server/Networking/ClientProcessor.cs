using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol;
using CSharp_SMTP_Server.Protocol.Commands;

namespace CSharp_SMTP_Server.Networking
{
	internal class ClientProcessor : IDisposable
	{
		internal ClientProcessor(TcpClient c, Listener l, bool secure)
		{
			_listener = l;
			_buffer = new byte[BufferSize];
			_client = c;
			_innerStream = c.GetStream();
			_stream = _innerStream;
			_encoder = new UTF8Encoding();
			RemoteEndPoint = _client.Client.RemoteEndPoint;
			Secure = secure && _listener.Server.Certificate != null;

			_clientThread = new Thread(Receive)
			{
				Name = "Receive thread",
				IsBackground = true
			};

			if (Secure)
			{
				_stream = new SslStream(_innerStream, true);
				((SslStream)_stream).AuthenticateAsServer(_listener.Server.Certificate, false, _listener.Server.Options.Protocols, true);
			}

			WriteText($"220 {_listener.Server.Options.ServerName} ESMTP");
		}

		public const ushort BufferSize = 1024;

		internal readonly EndPoint RemoteEndPoint;

		private readonly TcpClient _client;
		private readonly NetworkStream _innerStream;
		private Stream _stream;
		private readonly Thread _clientThread;
		private readonly Listener _listener;
		private byte[] _buffer;
		private readonly UTF8Encoding _encoder;

		internal MailTransaction Transaction;
		internal StringBuilder DataBuilder;

		internal bool Secure { get; private set; }
		internal ushort CaptureData;
		internal string Username, TempUsername;
		private ushort _protocolVersion;

		private void Receive()
		{
			while (true)
			{
				if (_client.Available == 0)
				{
					Thread.Sleep(2);
					continue;
				}

				using (var memoryStream = new MemoryStream())
				{
					var bytesRead = 0;
					while ((bytesRead = _stream.Read(_buffer, 0, BufferSize)) > 0)
						memoryStream.Write(_buffer, 0, bytesRead);

					ProcessResponse(_encoder.GetString(memoryStream.ToArray()));
				}
			}
		}

		internal void WriteText(string text) => _stream.Write(_encoder.GetBytes(text));

		internal void WriteCode(ushort code) => SMTPCodes.SendCode(this, code);

		internal SMTPServer Server => _listener.Server;

		private void ProcessResponse(string response)
		{
			response = response.Trim();

			switch (CaptureData)
			{
				case 1:
					TransactionCommands.ProcessData(this, response);
					return;

				case 2:
				case 3:
				case 4:
					AuthenticationCommands.ProcessData(this, response);
					return;
			}

			var command = string.Empty;
			var data = string.Empty;

			if (response.Contains(":")) command = response.Substring(0, response.IndexOf(":", StringComparison.Ordinal)).ToUpper().TrimEnd();
			else if (response.Contains(" "))
				command = response.Substring(0, response.IndexOf(" ", StringComparison.Ordinal)).ToUpper().TrimEnd();
			else command = response.ToUpper();

			if (command.Length != response.Length)
				data = response.Substring(command.Length).TrimStart();

			if (command.StartsWith("EHLO"))
			{
				Transaction = null;
				_protocolVersion = 1;
				WriteText($"250 {_listener.Server.Options.ServerName} at your service");
				if (_listener.Server.AuthLogin != null) WriteText("250-AUTH LOGIN PLAIN");
				if (!Secure && _listener.Server.Certificate != null) WriteText("250-STARTTLS");
			}
			else if (command.StartsWith("HELO"))
			{
				Transaction = null;
				_protocolVersion = 2;
				WriteText($"250 {_listener.Server.Options.ServerName} at your service");
			}
			else if (_protocolVersion > 0)
			{
				switch (command)
				{
					case "HELP":
						WriteText("250 There is no help for you");
						break;

					case "AUTH":
						AuthenticationCommands.ProcessCommand(this, data);
						break;

					case "STARTTLS":
						if (Secure)
						{
							WriteCode(503);
							return;
						}

						if (_listener.Server.Certificate == null)
						{
							WriteCode(502);
							return;
						}

						_stream = new SslStream(_innerStream, true);
						Secure = true;
						((SslStream)_stream).AuthenticateAsServer(_listener.Server.Certificate, false, _listener.Server.Options.Protocols, true);
						break;

					case "NOOP":
						WriteCode(250);
						break;

					case "QUIT":
						WriteText($"221 {_listener.Server.Options.ServerName} Service closing transmission channel");
						Dispose();
						break;

					case "RSET":
					case "MAIL FROM":
					case "RCPT TO":
					case "DATA":
						TransactionCommands.ProcessCommand(this, command, data);
						break;

					case "VRFY":
						WriteCode(252);
						break;

					default:
						WriteCode(502);
						break;
				}
			}
			else WriteCode(502);
		}

		public void Dispose()
		{
			Transaction = null;
			_clientThread.Abort();

			_innerStream?.Close(200);
			_innerStream?.Dispose();

			_stream?.Close();
			_stream?.Dispose();

			_client?.Close();
			_client?.Dispose();
			
			if (_listener != null && _listener.ClientProcessors.Contains(this))
				_listener.ClientProcessors.Remove(this);
		}

		private string AuthPlain(string input)
		{
			var auth = Misc.Base64.Base64Decode(input);
			if (!auth.Contains('\0')) return null;
			var split = auth.Split('\0');
			if (split.Length != 3) return null;
			return _listener.Server.AuthLogin.AuthPlain(split[0], split[1], split[2], _client.Client.RemoteEndPoint,
				Secure) ? split[1] : null;
		}
	}
}
