using System;
using System.Collections.Generic;

namespace CSharp_SMTP_Server.Misc
{
	/// <summary>
	/// Parser for email message.
	/// </summary>
	public static class EmailParser
	{
		/// <summary>
		/// Parses message headers.
		/// </summary>
		/// <param name="message">Received message</param>
		/// <param name="bodyStartIndex">Line number where message body starts</param>
		/// <returns>Headers of the email message</returns>
		public static Dictionary<string, List<string>> ParseHeaders(string message, out int bodyStartIndex)
		{
			var hs = new Dictionary<string, List<string>>();

			var split = message.Split('\n');
			for (bodyStartIndex = 0; bodyStartIndex < split.Length; bodyStartIndex++)
			{
				if (string.IsNullOrWhiteSpace(split[bodyStartIndex])) break;
				if (split[bodyStartIndex].StartsWith(" ", StringComparison.Ordinal)) continue;
				if (!split[bodyStartIndex].Contains(':', StringComparison.Ordinal)) break;

				var key = split[bodyStartIndex][..split[bodyStartIndex].IndexOf(": ", StringComparison.Ordinal)];
				var content = split[bodyStartIndex][(split[bodyStartIndex].IndexOf(": ", StringComparison.Ordinal) + 1)..].TrimEnd();

				for (var j = bodyStartIndex + 1; j < split.Length; j++)
				{
					if (string.IsNullOrWhiteSpace(split[j]) || !char.IsWhiteSpace(split[j][0]))
						break;

					var tr = split[j].TrimEnd();
					if (tr.Length > 1)
					{
						bodyStartIndex++;
						content += " " + tr[1..];
						continue;
					}

					break;
				}

				if (!hs.ContainsKey(key))
					hs.Add(key, new List<string>()
					{
						content
					});
				else hs[key].Add(content);
			}

			return hs;
		}

		/// <summary>
		/// Adds a header to an email message
		/// </summary>
		/// <param name="name">Header name</param>
		/// <param name="value">Header value</param>
		/// <param name="body">Email message body</param>
		public static void AddHeader(string name, string value, ref string body)
		{
			body = $"{name}: {value}\r\n{body}";
		}
	}
}