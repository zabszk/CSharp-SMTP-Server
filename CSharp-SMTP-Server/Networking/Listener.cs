using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CSharp_SMTP_Server.Networking
{
	public class Listener : IDisposable
	{
		private readonly TcpListener _listener;
		private readonly Thread _listenerThread;
		private readonly IPEndPoint _ipEndPoint;
		internal readonly List<ClientProcessor> ClientProcessors;
		internal readonly SMTPServer Server;

		internal Listener(IPAddress address, ushort port, SMTPServer s)
		{
			Server = s;
			ClientProcessors = new List<ClientProcessor>();

			_ipEndPoint = new IPEndPoint(address, port);
			_listener = new TcpListener(_ipEndPoint);
			_listenerThread = new Thread(Listen)
			{
				Name = "Listening on port " + port,
				IsBackground = true
			};
		}

		internal void Start() => _listenerThread.Start();

		private void Listen()
		{
			_listener.Start(200);
			while (true)
			{
				var client = _listener.AcceptTcpClient();
				ClientProcessors.Add(new ClientProcessor(client, this));
			}
		}

		public void Dispose()
		{
			_listenerThread.Abort();
			_listener.Stop();
		}
	}
}
