package goip

var _ ExtendedIdentifierString = WrappedIPAddressString{}

// ExtendedIdentifierString is a common interface for strings that identify hosts,
// namely [IPAddressString], [MACAddressString] and [HostName].
type ExtendedIdentifierString interface {
	HostIdentifierString
	GetAddress() AddressType         // returns the identified address or nil if none
	ToAddress() (AddressType, error) // returns the identified address or an error
	Unwrap() HostIdentifierString    // returns the wrapped IPAddressString, MACAddressString or HostName as an interface, HostIdentifierString
}

// WrappedIPAddressString wraps an IPAddressString to get an ExtendedIdentifierString,
// an extended polymorphic type.
type WrappedIPAddressString struct {
	*IPAddressString
}

// Unwrap returns the wrapped IPAddressString as an interface, HostIdentifierString.
func (str WrappedIPAddressString) Unwrap() HostIdentifierString {
	res := str.IPAddressString
	if res == nil {
		return nil
	}
	return res
}

// ToAddress returns the identified address or an error.
func (str WrappedIPAddressString) ToAddress() (AddressType, error) {
	addr, err := str.IPAddressString.ToAddress()
	if err != nil {
		return nil, err
	}
	return addr, nil
}

// GetAddress returns the identified address or nil if none.
func (str WrappedIPAddressString) GetAddress() AddressType {
	if addr := str.IPAddressString.GetAddress(); addr != nil {
		return addr
	}
	return nil
}

// WrappedMACAddressString wraps a MACAddressString to get an ExtendedIdentifierString.
type WrappedMACAddressString struct {
	*MACAddressString
}
