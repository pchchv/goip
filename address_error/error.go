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

// SizeMismatchError is an error that occurs when trying to perform an operation
// that requires address elements of the same size when the provided arguments are not equal in size.
type SizeMismatchError interface {
	IncompatibleAddressError
}

// IncompatibleAddressError represents situations where an address, address section,
// address segment or address string represents a valid type or format,
// but that type does not match the required type or format for that operation.
//
// For example:
//
//   - producing non-segmented hex, octal or base 85 strings from a subnet with a range that cannot be represented as a single range of values,
//   - masking subnets in a way that produces a non-contiguous range of values in a segment,
//   - reversing values that are not reversible,
//   - producing strings that are single-segment ranges from subnets which cannot be represented that way,
//   - producing new formats for which the range of values are incompatible with the new segments (EUI-64, IPv4 inet_aton formats, IPv4 embedded within IPv6, dotted MAC addresses from standard mac addresses, reverse-DNS strings), or
//   - using a subnet for an operation that requires a single address, such as with ToCanonicalHostName in IPAddress
type IncompatibleAddressError interface {
	AddressError
}
