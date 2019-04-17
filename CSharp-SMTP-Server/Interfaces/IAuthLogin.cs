using System.Net;

namespace CSharp_SMTP_Server.Interfaces
{
	public interface IAuthLogin
	{
		bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password, EndPoint remoteEndPoint,
			bool secureConnection);

		bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection);
	}
}
