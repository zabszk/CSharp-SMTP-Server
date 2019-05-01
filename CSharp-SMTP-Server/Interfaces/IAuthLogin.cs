using System.Net;

namespace CSharp_SMTP_Server.Interfaces
{
	/// <summary>
	/// Interface for handling authentication.
	/// </summary>
	public interface IAuthLogin
	{
        /// <summary>
        /// Handles "AUTH PLAIN" authentication.
        /// </summary>
        /// <param name="authorizationIdentity">Authorization identity</param>
        /// <param name="authenticationIdentity">Authentication identity</param>
        /// <param name="password">Password</param>
        /// <param name="remoteEndPoint">Remote endpoint of the connection</param>
        /// <param name="secureConnection">Is connection encrypted</param>
        /// <returns>True if authentication was successful, false otherwise.</returns>
        bool AuthPlain(string authorizationIdentity, string authenticationIdentity, string password, EndPoint remoteEndPoint,
			bool secureConnection);

		/// <summary>
		/// Handles "AUTH LOGIN" authentication.
		/// </summary>
		/// <param name="login">Username</param>
		/// <param name="password">Password</param>
		/// <param name="remoteEndPoint">Remote endpoint of the connection</param>
		/// <param name="secureConnection">Is connection encrypted</param>
		/// <returns>True if authentication was successful, false otherwise.</returns>
		bool AuthLogin(string login, string password, EndPoint remoteEndPoint, bool secureConnection);
	}
}
