namespace CSharp_SMTP_Server.Protocol.Responses
{
	/// <summary>
	/// User check codes defined in RFC
	/// </summary>
	public enum UserExistsCodes
	{
#pragma warning disable CS1591
		DestinationAddressValid = 0,
		BadDestinationMailboxAddress = 1,
		BadDestinationSystemAddress = 2,
		DestinationMailboxAddressAmbiguous = 3,
		DestinationAddressHasMovedAndNoForwardingAddress = 4,
		BadSendersSystemAddress = 5
#pragma warning restore CS1591
	}
}