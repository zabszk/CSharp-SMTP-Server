using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
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
			Secure = secure && Server.Certificate != null;

			_clientThread = new Thread(Receive)
			{
				Name = "Receive thread",
				IsBackground = true
			};
			_clientThread.Start();

			if (Secure)
			{
				_stream = new SslStream(_innerStream, true);
				((SslStream)_stream).AuthenticateAsServer(Server.Certificate, false, Server.Options.Protocols, true);
			}

			WriteText($"220 {Server.Options.ServerName} ESMTP");
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
		private bool _dispose;

		private void Receive()
		{
			while (!_dispose)
			{
				if (_client.Available == 0)
				{
					Thread.Sleep(10);
					continue;
				}

				using (var memoryStream = new MemoryStream())
				{
					while (_client.Available > 0)
					{
						var bytesRead = _stream.Read(_buffer, 0, BufferSize);
						memoryStream.Write(_buffer, 0, bytesRead);
					}

					ProcessResponse(_encoder.GetString(memoryStream.ToArray()));
				}
			}
		}

		internal void WriteText(string text)
		{
			var encoded = _encoder.GetBytes(text + "\n\r");
			_stream.Write(encoded, 0, encoded.Length);
		}

		internal void WriteCode(ushort code) => SMTPCodes.SendCode(this, code);
		internal void WriteCode(ushort code, string enhanced) => SMTPCodes.SendCode(this, code, enhanced);
		internal void WriteCode(ushort code, string enhanced, string text) => SMTPCodes.SendCode(this, code, enhanced, text);

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

			if (command == "EHLO")
			{
				Transaction = null;
				_protocolVersion = 1;
				WriteText($"250 {Server.Options.ServerName} at your service");
				if (Server.AuthLogin != null) WriteText("250-AUTH LOGIN PLAIN");
				if (!Secure && Server.Certificate != null) WriteText("250-STARTTLS");
			}
			else if (command == "HELO")
			{
				Transaction = null;
				_protocolVersion = 2;
				WriteText($"250 {Server.Options.ServerName} at your service");
			}
			else if (_protocolVersion > 0)
			{
				switch (command)
				{
					case "HELP":
						WriteCode(214, "2.0.0");
						break;

					case "AUTH":
						AuthenticationCommands.ProcessCommand(this, data);
						break;

					case "STARTTLS":
						if (Secure)
						{
							WriteCode(503, "5.5.1");
							return;
						}

						if (Server.Certificate == null)
						{
							WriteCode(502, "5.5.1");
							return;
						}

						_stream = new SslStream(_innerStream, true);
						Secure = true;
						((SslStream)_stream).AuthenticateAsServer(Server.Certificate, false, Server.Options.Protocols, true);
						break;

					case "NOOP":
						WriteCode(250, "2.0.0");
						break;

					case "QUIT":
						WriteCode(221, "2.0.0");
						Dispose();
						break;

					case "RSET":
					case "MAIL FROM":
					case "RCPT TO":
					case "DATA":
						TransactionCommands.ProcessCommand(this, command, data);
						break;

					case "VRFY":
						WriteCode(252, "5.5.1");
						break;

					default:
						WriteCode(502, "5.5.1");
						break;
				}
			}
			else WriteCode(503, "5.5.1", "EHLO/HELO first.");
		}

		public void Dispose()
		{
			Transaction = null;
			_dispose = true;

			_innerStream?.Close(200);
			_innerStream?.Dispose();

			_stream?.Close();
			_stream?.Dispose();

			_client?.Close();
			_client?.Dispose();
			
			if (_listener != null && _listener.ClientProcessors.Contains(this))
				_listener.ClientProcessors.Remove(this);
		}
	}
}
