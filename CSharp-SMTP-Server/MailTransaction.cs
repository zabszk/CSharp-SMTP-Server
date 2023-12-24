using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using CSharp_SMTP_Server.Networking;
using CSharp_SMTP_Server.Protocol;
using CSharp_SMTP_Server.Protocol.DKIM;
using MimeKit;

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
			RawBody = string.Empty;
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
		/// Raw message body
		/// </summary>
		public string RawBody;

		/// <summary>
		/// Subject of the message
		/// </summary>
		public string? Subject => ParsedMessage.Subject;

		/// <summary>
		/// Recipients specified in the transaction
		/// </summary>
		public List<string> DeliverTo { get; private set; }

		/// <summary>
		/// Sender of the message specified in the header
		/// Note that this is NOT validated using SPF.
		/// </summary>
		public string? GetFrom => ParsedMessage.From.Count > 0 ? ParsedMessage.From[0].Name : null;

		/// <summary>
		/// Recipients specified in the header (To)
		/// </summary>
		public IEnumerable<string> GetTo() => ParsedMessage.To.Select(x => x.Name);

		/// <summary>
		/// Recipients specified in the header (CC)
		/// </summary>
		public IEnumerable<string> GetCc() => ParsedMessage.Cc.Select(x => x.Name);

		/// <summary>
		/// Recipients specified in the header (BCC)
		/// </summary>
		public IEnumerable<string> GetBcc() => ParsedMessage.Bcc.Select(x => x.Name);

		/// <summary>
		/// Returns email body without headers
		/// </summary>
		/// <returns>Email body</returns>
		public string? GetMessageBody() => ParsedMessage.TextBody ?? ParsedMessage.HtmlBody;

		/// <summary>
		/// Parsed email message
		/// </summary>
		public MimeMessage ParsedMessage
		{
			get
			{
				if (_parsedMessage != null) return _parsedMessage;

				_parsedMessage = MimeMessage.Load(new MemoryStream(Encoding.UTF8.GetBytes(RawBody)));
				return _parsedMessage;
			}
		}

		private MimeMessage? _parsedMessage;

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
		/// DKIM validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		// ReSharper disable once UnusedAutoPropertyAccessor.Global
		public DkimValidator.DkimValidationResult DKIMValidationResult { get; internal set; }

		/// <summary>
		/// DMARC validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		// ReSharper disable once UnusedAutoPropertyAccessor.Global
		public ValidationResult DMARCValidationResult { get; internal set; }

		/// <summary>
		/// Adds a header to the email message
		/// </summary>
		/// <param name="name">Header name</param>
		/// <param name="value">Header value</param>
		public void AddHeader(string name, string value)
		{
			RawBody = $"{name}: {value}\r\n{RawBody}";
			ParsedMessage.Headers.Add(name, value);
		}

		/// <inheritdoc />
		public object Clone()
		{
			return new MailTransaction(From, FromDomain, SPFValidationResult)
			{
				AuthenticatedUser = AuthenticatedUser,
				RawBody = RawBody,
				_parsedMessage = ParsedMessage,
				RemoteEndPoint = RemoteEndPoint,
				DeliverTo = DeliverTo,
				Encryption = Encryption
			};
		}
	}
}