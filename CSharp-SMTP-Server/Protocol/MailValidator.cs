using System.Threading.Tasks;

namespace CSharp_SMTP_Server.Protocol;

/// <summary>
/// Mail Transaction validation interface
/// </summary>
public interface IMailValidator
{
	/// <summary>
	/// Validates Mail Transaction
	/// </summary>
	/// <param name="transaction">Transaction to validate</param>
	/// <returns>Validation result</returns>
	public Task<ValidationResult> ValidateTransaction(MailTransaction transaction);
}