package address_error

// AddressError is a type used by all library errors in order to be able to provide internationalized error messages.
type AddressError interface {
	error
	// GetKey allows users to implement their own i18n error messages.
	GetKey() string
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
