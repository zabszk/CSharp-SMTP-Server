using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol;

namespace CSharp_SMTP_Server
{
	/// <summary>
	/// SMTP transaction
	/// </summary>
	public class MailTransaction : ICloneable
	{
		internal MailTransaction(string from, string fromDomain, ValidationResult validationResult)
		{
			From = from;
			FromDomain = fromDomain;
			SPFValidationResult = validationResult;
			DeliverTo = new List<string>();
			AuthenticatedUser = null;
		}

		/// <summary>
		/// Mail sender
		/// </summary>
		public readonly string From;

		/// <summary>
		/// Mail sender domain
		/// If SPF validation is enabled, this domain is validated
		/// </summary>
		public readonly string FromDomain;

		/// <summary>
		/// Raw message body (with headers)
		/// </summary>
		public string? RawBody;

		/// <summary>
		/// Index on which body of the message starts (after the headers)
		/// </summary>
		public int BodyStartIndex { get; internal set; }

		/// <summary>
		/// Subject of the message
		/// </summary>
		public string? Subject => TryGetHeader("Subject", out var value) ? value : null;

		/// <summary>
		/// Recipients specified in the transaction
		/// </summary>
		public List<string> DeliverTo { get; private set; }

		/// <summary>
		/// Sender of the message specified in the header
		/// Note that this is NOT validated using SPF.
		/// </summary>
		public string? GetFrom => TryGetHeader("From", out var value) ? value : null;

		/// <summary>
		/// Recipients specified in the header (To)
		/// </summary>
		public IEnumerable<string> GetTo() => ParseAddresses("To");

		/// <summary>
		/// Recipients specified in the header (CC)
		/// </summary>
		public IEnumerable<string> GetCc() => ParseAddresses("cc");

		/// <summary>
		/// Recipients specified in the header (BCC)
		/// </summary>
		public IEnumerable<string> GetBcc() => ParseAddresses("bcc");

		/// <summary>
		/// Returns email body without headers
		/// </summary>
		/// <returns>Email body</returns>
		public string? GetMessageBody() => RawBody == null ? null : string.Join("\r\n", RawBody.Split('\n').Skip(BodyStartIndex).Select(x => x.TrimEnd('\r')));

		/// <summary>
		/// Returns email addresses from a header
		/// </summary>
		/// <param name="header">Header to parse</param>
		/// <returns>Email addresses</returns>
		// ReSharper disable once MemberCanBePrivate.Global
		public IEnumerable<string> ParseAddresses(string header)
		{
			if (!TryGetHeader(header, out var t)) yield break;

			while (t!.Contains('<', StringComparison.Ordinal))
			{
				if (!t.Contains('>', StringComparison.Ordinal)) yield break;
				var address = t[(t.IndexOf("<", StringComparison.Ordinal) + 1)..];
				var i = address.IndexOf(">", StringComparison.Ordinal);
				yield return address[..i];
				if (i + 1 >= t.Length) yield break;
				t = address[(i + 1)..];
			}
		}

		/// <summary>
		/// Attempts to get a header from the message
		/// </summary>
		/// <param name="header">Header name</param>
		/// <param name="value">Returned header value</param>
		/// <returns>Indicates whether the operation was successful or not</returns>
		// ReSharper disable once MemberCanBePrivate.Global
		public bool TryGetHeader(string header, out string? value)
		{
			value = null;

			if (Headers == null || !Headers.TryGetValue(header, out var tt))
				return false;

			if (tt.Count != 1)
				return false;

			value = tt[0];
			return true;
		}

		/// <summary>
		/// Returns amount of a specified header
		/// </summary>
		/// <param name="header">Header to count</param>
		/// <returns>Amount of the specified header</returns>
		public int HeadersAmount(string header)
		{
			if (Headers == null || !Headers.TryGetValue(header, out var tt))
				return 0;

			return tt.Count;
		}

		/// <summary>
		/// Email headers
		/// </summary>
		public Dictionary<string, List<string>>? Headers { get; internal set; }

		/// <summary>
		/// Endpoint of the client/server sending the message
		/// </summary>
		public IPEndPoint? RemoteEndPoint { get; internal set; }

		/// <summary>
		/// Username of authenticated users. Empty if user is not authenticated.
		/// </summary>
		public string? AuthenticatedUser { get; internal set; }

		/// <summary>
		/// Encryption used for receiving this message
		/// </summary>
		public ConnectionEncryption Encryption { get; internal set; }

		/// <summary>
		/// SPF validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		public readonly ValidationResult SPFValidationResult;

		/// <summary>
		/// DMARC validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		public ValidationResult DMARCValidationResult { get; internal set; }

		/// <inheritdoc />
		public object Clone()
		{
			return new MailTransaction(From, FromDomain, SPFValidationResult)
			{
				AuthenticatedUser = AuthenticatedUser,
				RawBody = RawBody,
				Headers = Headers,
				RemoteEndPoint = RemoteEndPoint,
				DeliverTo = DeliverTo,
				Encryption = Encryption,
				BodyStartIndex = BodyStartIndex
			};
		}
	}
}