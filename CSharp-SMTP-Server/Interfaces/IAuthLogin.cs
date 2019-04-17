using System.Net;

namespace CSharp_SMTP_Server.Interfaces
{
	public interface IAuthLogin
	{
		bool AuthLogin(string login, string password, EndPoint remoteIpEndPoint, bool secureConnection);
	}
}
