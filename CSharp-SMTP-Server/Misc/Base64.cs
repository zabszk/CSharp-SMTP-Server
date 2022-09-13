using System;
using System.Text;

namespace CSharp_SMTP_Server.Misc
{
	internal class Base64
	{
		internal static string Base64Encode(string plainText)
		{
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			return Convert.ToBase64String(plainTextBytes);
		}

		internal static string? Base64Decode(string base64EncodedData)
		{
			try
			{
				var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
				return Encoding.UTF8.GetString(base64EncodedBytes);
			}
			catch
			{
				return null;
			}
		}
	}
}
