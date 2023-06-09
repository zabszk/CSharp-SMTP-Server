using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp;

internal class AuthenticationInterface : IAuthLogin
{
	//123 is password for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)

	public Task<bool> AuthPlain(string authorizationIdentity, string authenticationIdentity, string password,
		EndPoint remoteEndPoint,
		bool secureConnection) => Task.FromResult(password == "123");

	public Task<bool> AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection) =>
		Task.FromResult(password == "123");
}