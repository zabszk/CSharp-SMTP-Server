namespace CSharp_SMTP_Server.Interfaces
{
	/// <summary>
	/// Interface for handling server errors.
	/// </summary>
	public interface ILogger
	{
		/// <summary>
		/// Called when error occurs.
		/// </summary>
		/// <param name="text">Error content</param>
		void LogError(string text);

		/// <summary>
		/// Called when debug mode.
		/// </summary>
		/// <param name="text">Error content</param>
		void LogDebug(string text);
	}
}