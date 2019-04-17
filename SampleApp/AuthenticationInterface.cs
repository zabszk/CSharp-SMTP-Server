using System.Net;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp
{
	class AuthenticationInterface : IAuthLogin
	{
		public bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
			EndPoint remoteEndPoint,
			bool secureConnection) => password == "123";

		public bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
			password == "123";
	}
}
