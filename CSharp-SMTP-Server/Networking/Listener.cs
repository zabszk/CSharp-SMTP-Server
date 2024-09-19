﻿using System;
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
						ClientProcessors.Add(new ClientProcessor(client, this, _secure));
					}
					catch (Exception e)
					{
						if (!_dispose)
							Server.LoggerInterface?.LogError("[Listening inner loop] Exception: " + e.Message);
					}
				}

				Server.LoggerInterface?.LogError($"[Listening inner loop] Loop exited. _dispose={_dispose}. Stack trace: {new System.Diagnostics.StackTrace()}");
			}
			catch (Exception e)
			{
				Server.LoggerInterface?.LogError("[Listening] Exception: " + e.Message);
			}

			Server.LoggerInterface?.LogError($"[Listening] Loop exited. _dispose={_dispose}. Stack trace: {new System.Diagnostics.StackTrace()}");
		}

		public void Dispose()
		{
			Server.LoggerInterface?.LogError($"Listener.Dispose() called. _dispose={_dispose}. Stack trace: {new System.Diagnostics.StackTrace()}");
			_dispose = true;

			_listener.Stop();

			foreach (var processor in ClientProcessors)
				processor.Dispose(true, true);
		}
	}
}