using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Protocol;

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
			_secure = secure && _listener.Server.Certificate != null;

			_clientThread = new Thread(Receive)
			{
				Name = "Receive thread",
				IsBackground = true
			};

			if (_secure)
			{
				_stream = new SslStream(_innerStream, true);
				((SslStream)_stream).AuthenticateAsServer(_listener.Server.Certificate, false, _listener.Server.Options.Protocols, true);
			}

			WriteText($"220 {_listener.Server.Options.ServerName} ESMTP");
		}

		public const ushort BufferSize = 1024;

		private readonly TcpClient _client;
		private readonly NetworkStream _innerStream;
		private Stream _stream;
		private readonly Thread _clientThread;
		private readonly Listener _listener;
		private MailTransaction _transaction;
		private StringBuilder _dataBuilder;
		private byte[] _buffer;
		private readonly UTF8Encoding _encoder;
		private bool _secure;
		private string _username, _tUsername;
		private ushort _captureData;
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

		private void ProcessResponse(string response)
		{
			response = response.Trim();

			if (_captureData == 1)
			{
				if (response == ".")
				{
					_captureData = 0;
					_transaction.Body = _dataBuilder.ToString();
					if (!string.IsNullOrEmpty(_username)) _transaction.AuthenticatedUser = _username;

					Task.Run(() => _listener.Server.DeliverMessage(_transaction));
					_transaction = null;

					WriteCode(250);
					return;
				}

				_dataBuilder.AppendLine(response);
				return;
			}

			if (_captureData == 2)
			{
				_tUsername = Misc.Base64.Base64Decode(response);
				_captureData = 3;
				WriteText("334 UGFzc3dvcmQ6");

				return;
			}

			if (_captureData == 3)
			{
				_captureData = 0;

				if (_listener.Server.AuthLogin == null)
				{
					WriteText("454 4.7.0  Temporary authentication failure");
					return;
				}

				if (_listener.Server.AuthLogin.AuthLogin(_tUsername, response, _client.Client.RemoteEndPoint, _secure))
				{
					WriteText("235 2.7.0  Authentication Succeeded");
					_username = _tUsername;
				}
				else
					WriteText("535 5.7.8  Authentication credentials invalid");

				_tUsername = null;
				return;
			}
			var command = response.ToUpper();

			if (command.StartsWith("EHLO"))
			{
				_transaction = null;
				_protocolVersion = 1;
				WriteText($"250 {_listener.Server.Options.ServerName} at your service");
				if (_listener.Server.AuthLogin != null) WriteText("250-AUTH LOGIN");
				if (!_secure && _listener.Server.Certificate != null) WriteText("250-STARTTLS");
			}
			else if (command.StartsWith("HELO"))
			{
				_transaction = null;
				_protocolVersion = 2;
				WriteText($"250 {_listener.Server.Options.ServerName} at your service");
			}
			else if (_protocolVersion > 0)
			{
				if (command.StartsWith("HELP")) WriteText("250 There is no help for you");
				else if (command.StartsWith("AUTH LOGIN"))
				{
					if (_listener.Server.AuthLogin == null)
					{
						WriteCode(502);
						return;
					}

					if (_listener.Server.Options.RequireEncryptionForAuth && !_secure)
					{
						WriteText("538 5.7.11  Encryption required for requested authentication mechanism");
						return;
					}

					_captureData = 2;
					WriteText("334 VXNlcm5hbWU6");
				}
				else if (command.StartsWith("NOOP")) WriteCode(250);
				else if (command.StartsWith("QUIT"))
				{
					WriteText($"221 {_listener.Server.Options.ServerName} Service closing transmission channel");
					Dispose();
				}
				else if (command.StartsWith("STARTTLS"))
				{
					if (_secure)
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
					_secure = true;
					((SslStream) _stream).AuthenticateAsServer(_listener.Server.Certificate, false, _listener.Server.Options.Protocols, true);
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
					emailFrom = emailFrom.Substring(0, from.IndexOf(">", StringComparison.Ordinal));

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
					emailTo = emailTo.Substring(0, to.IndexOf(">", StringComparison.Ordinal));

					if (string.IsNullOrWhiteSpace(emailTo))
					{
						WriteCode(501);
						return;
					}

					if (!_listener.Server.MailDeliveryInterface.UserExists(emailTo))
					{
						WriteCode(550);
						return;
					}

					_transaction.To.Add(emailTo);
					WriteCode(250);
				}
				else if (command == "DATA")
				{
					if (_transaction == null || _transaction.To.Count == 0)
					{
						WriteCode(503);
						return;
					}

					_dataBuilder = new StringBuilder();
					_captureData = 1;

					WriteCode(354);
				}
				else WriteCode(502);
			}
			else WriteCode(502);
		}

		public void Dispose()
		{
			_transaction = null;
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
	}
}
