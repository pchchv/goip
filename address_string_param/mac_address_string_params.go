package address_string_param

const (
	MAC48Len          MACAddressLen = "MAC48" // indicates 48-bit MAC addresses
	EUI64Len          MACAddressLen = "EUI64" // indicates 64-bit MAC addresses
	UnspecifiedMACLen MACAddressLen = ""      // indicates unspecified bit-length MAC addresses
)

// MACAddressLen is an option indicating a MAC address length.
type MACAddressLen string

// MACAddressStringFormatParams provides format parameters for MAC addresses,
// indicating what formatting is allowed.
type MACAddressStringFormatParams interface {
	AddressStringFormatParams
	// AllowsShortSegments allows segments that are just a single hex digit and not two.
	AllowsShortSegments() bool
}
