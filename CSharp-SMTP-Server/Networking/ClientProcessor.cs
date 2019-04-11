using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

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
		}

		public const int BufferSize = 1024;

		private readonly TcpClient _client;
		private readonly NetworkStream _stream;
		private readonly Thread _clientThread;
		private readonly Listener _listener;
		private byte[] _buffer;
		private UTF8Encoding _encoder;

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

		private void ProcessResponse(string response)
		{

		}

		public void Dispose()
		{
			_clientThread.Abort();
			_client?.Dispose();
			_stream?.Dispose();

			if (_listener != null && _listener.ClientProcessors.Contains(this))
				_listener.ClientProcessors.Remove(this);
		}
	}
}
