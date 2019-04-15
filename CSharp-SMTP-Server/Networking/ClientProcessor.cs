using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server.Networking
{
	internal class ClientProcessor : IDisposable
	{
		internal ClientProcessor(TcpClient c, Listener l)
		{
			_listener = l;
			_buffer = new byte[BufferSize];
			_client = c;
			_stream = c.GetStream();
			_encoder = new UTF8Encoding();

			_clientThread = new Thread(Receive)
			{
				Name = "Receive thread",
				IsBackground = true
			};

			WriteText($"220 {_listener.Server.Options.ServerName} ESMTP");
		}

		public const int BufferSize = 1024;

		private readonly TcpClient _client;
		private readonly NetworkStream _stream;
		private readonly Thread _clientThread;
		private readonly Listener _listener;
		private MailTransaction _transaction;
		private StringBuilder _dataBuilder;
		private byte[] _buffer;
		private UTF8Encoding _encoder;
		private bool _captureData;

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

		internal void WriteCode(int code) => SMTPCodes.SendCode(this, code);

		private void ProcessResponse(string response)
		{
			response = response.Trim();

			if (_captureData)
			{
				if (response == ".")
				{
					_captureData = false;
					_transaction.Body = _dataBuilder.ToString();

					WriteCode(250);
					return;
				}
				_dataBuilder.AppendLine(response);
				return;
			}

			var command = response.ToUpper();

			if (command.StartsWith("EHLO") || command.StartsWith("HELO") || command.StartsWith("HELLO"))
			{
				_transaction = null;
				WriteText($"250 {_listener.Server.Options.ServerName} at your service");
			}
			else if (command.StartsWith("HELP")) WriteText("250 There is no help for you");
			else if (command.StartsWith("NOOP")) WriteCode(250);
			else if (command.StartsWith("QUIT"))
			{
				WriteText($"221 {_listener.Server.Options.ServerName} Service closing transmission channel");
				_stream.Close(200);
				_client.Close();
				Dispose();
			}
			else if (command.StartsWith("RSET"))
			{
				_transaction = null;
				WriteCode(250);
			}
			else if (command.StartsWith("VRFY")) WriteCode(252);
			else if (command.StartsWith("MAIL FROM:"))
			{
				var from = response.Substring(10).Trim();
				if (!from.Contains("<") || !from.Contains(">"))
				{
					WriteCode(501);
					return;
				}

				var emailFrom = from.Substring(from.IndexOf("<", StringComparison.Ordinal) + 1);
				emailFrom = from.Substring(0, from.IndexOf(">", StringComparison.Ordinal));

				if (string.IsNullOrWhiteSpace(emailFrom))
				{
					WriteCode(501);
					return;
				}

				_transaction = new MailTransaction()
				{
					From = emailFrom
				};

				WriteCode(250);
			}
			else if (command.StartsWith("RCPT TO:"))
			{
				if (_transaction == null)
				{
					WriteCode(503);
					return;
				}
				var to = response.Substring(8).Trim();

				if (!to.Contains("<") || !to.Contains(">"))
				{
					WriteCode(501);
					return;
				}

				var emailTo = to.Substring(to.IndexOf("<", StringComparison.Ordinal) + 1);
				emailTo = to.Substring(0, to.IndexOf(">", StringComparison.Ordinal));

				if (string.IsNullOrWhiteSpace(emailTo))
				{
					WriteCode(501);
					return;
				}

				_transaction.To = emailTo;
			}
			else if (command == "DATA")
			{
				if (_transaction == null || string.IsNullOrWhiteSpace(_transaction.To))
				{
					WriteCode(503);
					return;
				}

				_dataBuilder = new StringBuilder();
				_captureData = true;

				WriteCode(354);
			}
			else WriteCode(502);
		}

		public void Dispose()
		{
			_transaction = null;
			_clientThread.Abort();
			_client?.Dispose();
			_stream?.Dispose();

			if (_listener != null && _listener.ClientProcessors.Contains(this))
				_listener.ClientProcessors.Remove(this);
		}
	}
}
