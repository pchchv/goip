package address_error

// AddressError is a type used by all library errors in order to be able to provide internationalized error messages.
type AddressError interface {
	error
	// GetKey allows users to implement their own i18n error messages.
	GetKey() string
}

// AddressValueError occurs as a result of providing an invalid value for an address operation.
// Used when the address or address component is too large or small,
// when the prefix length is too large or small, or when prefixes in segments are inconsistent.
// Not used when constructing new address components.
// Not used when parsing strings to construct new address components,
// in which case AddressStringError is used instead.
type AddressValueError interface {
	AddressError
}

// AddressStringError represents errors in address string formats used to identify addresses.
type AddressStringError interface {
	HostIdentifierError
}

// HostIdentifierError represents errors in string formats used to identify hosts.
type HostIdentifierError interface {
	AddressError
}

// HostNameError represents errors in host name string formats used to identify hosts.
type HostNameError interface {
	HostIdentifierError
	// GetAddrError returns the underlying address error, or nil if none.
	GetAddrError() AddressError
}
