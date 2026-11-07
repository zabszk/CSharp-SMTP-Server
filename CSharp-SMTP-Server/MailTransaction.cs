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
		internal MailTransaction(string? ehloDomain, string from, string fromDomain, ValidationResult validationResult, ValidationResult ehloValidationResult)
		{
			EhloDomain = ehloDomain;
			From = from;
			FromDomain = fromDomain;
			SPFValidationResult = validationResult;
			EhloSPFValidationResult = ehloValidationResult;
			DeliverTo = new List<string>();
			AuthenticatedUser = null;
			RawBody = string.Empty;
		}

		/// <summary>
		/// Mail sender
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		public readonly string? EhloDomain;

		/// <summary>
		/// Mail sender (envelope MAIL FROM address).
		/// Empty string for the null reverse-path ("MAIL FROM:&lt;&gt;"), which is used by bounces and other delivery notifications.
		/// </summary>
		public readonly string From;

		/// <summary>
		/// Mail sender domain
		/// If SPF validation is enabled, this domain is validated.
		/// For the null reverse-path, this is the HELO/EHLO domain (RFC 7208, section 2.4), or an empty string if it's not a valid domain.
		/// </summary>
		public readonly string FromDomain;

		/// <summary>
		/// Raw message body.
		/// Setting it discards the cached <see cref="ParsedMessage"/>, so that it's always parsed from the current raw body.
		/// </summary>
		public string RawBody
		{
			get => _rawBody;
			set
			{
				_rawBody = value;
				_parsedMessage = null;
			}
		}

		private string _rawBody = string.Empty;

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
		public string? GetFrom => ParsedMessage.From.Mailboxes.Count() > 0 ? ParsedMessage.From.Mailboxes.First().Address : null;

		/// <summary>
		/// Recipients specified in the header (To)
		/// </summary>
		public IEnumerable<string> GetTo() => ParsedMessage.To.Mailboxes.Select(x => x.Address);

		/// <summary>
		/// Recipients specified in the header (CC)
		/// </summary>
		public IEnumerable<string> GetCc() => ParsedMessage.Cc.Mailboxes.Select(x => x.Address);

		/// <summary>
		/// Recipients specified in the header (BCC)
		/// </summary>
		public IEnumerable<string> GetBcc() => ParsedMessage.Bcc.Mailboxes.Select(x => x.Address);

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
		/// SPF validation result of EHLO domain
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		public readonly ValidationResult EhloSPFValidationResult;

		/// <summary>
		/// DKIM validation result
		/// </summary>
		// ReSharper disable once MemberCanBePrivate.Global
		// ReSharper disable once InconsistentNaming
		// ReSharper disable once UnusedAutoPropertyAccessor.Global
		public DkimValidator.DkimValidationResult DKIMValidationResult { get; internal set; } = new (ValidationResult.None);

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
			// Parse before modifying the raw body, otherwise the header would be parsed from the raw body and then added again
			var parsed = ParsedMessage;
			_rawBody = $"{name}: {value}\r\n{_rawBody}";
			parsed.Headers.Insert(0, name, value);
		}

		/// <inheritdoc />
		public object Clone()
		{
			return new MailTransaction(EhloDomain, From, FromDomain, SPFValidationResult, EhloSPFValidationResult)
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