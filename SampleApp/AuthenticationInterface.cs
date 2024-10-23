using System;
using System.Net;
using System.Threading.Tasks;
using CSharp_SMTP_Server.Interfaces;

namespace SampleApp;

internal class AuthenticationInterface : IAuthLogin
{
	//password is password for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)
	//authenticationIdentity is user for all users (NOT SECURE, ONLY FOR DEMO PURPOSES!)

	public Task<bool> CheckAuthCredentials(string authorizationIdentity, string authenticationIdentity, string password,
		EndPoint remoteEndPoint,
		bool secureConnection)
	{

		Console.WriteLine($"[VERB ] authorizationIdentity:{authorizationIdentity} authenticationIdentity:{authenticationIdentity} password:{password}");
		return Task.FromResult(authenticationIdentity == "user" && password == "password");
	}
}