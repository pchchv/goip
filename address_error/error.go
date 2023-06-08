package address_error

// AddressError is a type used by all library errors in order to be able to provide internationalized error messages.
type AddressError interface {
	error
	// GetKey allows users to implement their own i18n error messages.
	GetKey() string
}
