using System.Net;
using System.Threading.Tasks;

namespace CSharp_SMTP_Server.Interfaces
{
	/// <summary>
	/// Interface for handling client authentication.
	/// </summary>
	public interface IAuthLogin
	{
		/// <summary>
		/// Handles client authentication.
		/// </summary>
		/// <param name="authorizationIdentity">Authorization identity</param>
		/// <param name="authenticationIdentity">Authentication identity</param>
		/// <param name="password">Password</param>
		/// <param name="remoteEndPoint">Remote endpoint of the connection</param>
		/// <param name="secureConnection">Is connection encrypted</param>
		/// <returns>True if authentication was successful, false otherwise.</returns>
		Task<bool> CheckAuthCredentials(string authorizationIdentity, string authenticationIdentity, string password, EndPoint? remoteEndPoint,
			bool secureConnection);
	}
}