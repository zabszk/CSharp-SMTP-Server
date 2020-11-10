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
        /// <returns>Headers of the email message</returns>
        public static Dictionary<string, string> ParseHeaders(string message)
        {
            var hs = new Dictionary<string, string>();
            
            var split = message.Split('\n');
            for (var i = 0; i < split.Length; i++)
            {
                if (!split[i].Contains(":")) break;
                var s = split[i].TrimEnd('\r').Split(':');
                if (!s[1].StartsWith(" ")) continue;
                var content = s[1];
                for (var j = i + 1; j < split.Length; j++)
                {
                    if (split[j].Contains(":"))
                        break;
                    var tr = split[j].TrimEnd('\r');
                    if (tr.Length > 0 && char.IsWhiteSpace(tr[0]))
                    {
                        i++;
                        content += tr.Trim();
                    }
                    else break;
                }
                    
                hs.Add(s[0], content);
            }

            return hs;
        }
    }
}