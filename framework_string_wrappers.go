package goip

// ExtendedIdentifierString is a common interface for strings that identify hosts,
// namely [IPAddressString], [MACAddressString] and [HostName].
type ExtendedIdentifierString interface {
	HostIdentifierString
	GetAddress() AddressType         // returns the identified address or nil if none
	ToAddress() (AddressType, error) // returns the identified address or an error
	Unwrap() HostIdentifierString    // returns the wrapped IPAddressString, MACAddressString or HostName as an interface, HostIdentifierString
}
