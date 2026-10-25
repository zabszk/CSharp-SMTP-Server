using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace CSharp_SMTP_Server.Networking
{
	internal class Listener : IDisposable
	{
		internal readonly List<ClientProcessor> ClientProcessors;
		internal readonly SMTPServer Server;

		private readonly TcpListener _listener;
		private readonly Thread _listenerThread;
		private readonly bool _secure;
		private readonly object _clientsLock = new();
		private bool _dispose;

		internal Listener(IPAddress address, ushort port, SMTPServer s, bool secure, bool dualMode)
		{
			Server = s;
			_secure = secure;
			ClientProcessors = new List<ClientProcessor>();

			var ipEndPoint = new IPEndPoint(address, port);
			_listener = new TcpListener(ipEndPoint)
			{
				Server = { DualMode = dualMode }
			};
			_listenerThread = new Thread(Listen)
			{
				Name = "Listening on port " + port,
				IsBackground = true
			};
		}

		internal void Start() => _listenerThread.Start();

		private void Listen()
		{
			try
			{
				_listener.Start(200);
				while (!_dispose)
				{
					try
					{
						var client = _listener.AcceptTcpClient();
						var processor = new ClientProcessor(client, this, _secure);
						if (!TryAddProcessor(processor))
						{
							client.Dispose();
							continue;
						}
						_ = processor.Init();
					}
					catch (Exception e)
					{
						if (!_dispose)
							Server.LoggerInterface?.LogError("[Listening inner loop] Exception: " + e.Message);
					}
				}
			}
			catch (Exception e)
			{
				Server.LoggerInterface?.LogError("[Listening] Exception: " + e.Message);
			}
		}

		private bool TryAddProcessor(ClientProcessor processor)
		{
			lock (_clientsLock)
			{
				var limit = Server.Options.MaximumConcurrentClients;
				if (_dispose || (limit > 0 && ClientProcessors.Count >= limit))
					return false;

				ClientProcessors.Add(processor);
				return true;
			}
		}

		internal void RemoveProcessor(ClientProcessor processor)
		{
			lock (_clientsLock)
				ClientProcessors.Remove(processor);
		}

		public void Dispose()
		{
			_listener.Stop();

			lock (_clientsLock)
			{
				if (_dispose)
					return;

				_dispose = true;
				foreach (var processor in ClientProcessors)
					processor.Dispose(true, true);
			}
		}
	}
}
