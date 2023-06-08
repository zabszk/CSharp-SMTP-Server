namespace CSharp_SMTP_Server.Protocol.Responses
{
	public enum UserExistsCodes
	{
		DestinationAddressValid = 0,
		BadDestinationMailboxAddress = 1,
		BadDestinationSystemAddress = 2,
		DestinationMailboxAddressAmbiguous = 3,
		DestinationAddressHasMovedAndNoForwardingAddress = 4,
		BadSendersSystemAddress = 5
	}
}