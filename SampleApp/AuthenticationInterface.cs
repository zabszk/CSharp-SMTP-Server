using System.Net;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp
{
	class AuthenticationInterface : IAuthLogin
	{
		//123 is password for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)

		public bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
			EndPoint remoteEndPoint,
			bool secureConnection) => password == "123";

		public bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
			password == "123";
	}
}
