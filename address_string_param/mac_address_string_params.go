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

// MACAddressStringParams provides parameters for parsing MAC address strings.
// This allows you to control the validation performed by MACAddressString.
// MACAddressString uses the default MACAddressStringParams resolving instance if one is not specified.
// If you want to use parameters other than the default, use this interface.
// Immutable instances can be constructed using the MACAddressStringParamsBuilder.
type MACAddressStringParams interface {
	AddressStringParams
	// GetPreferredLen indicates whether an ambiguous address like * is considered to be MAC 6 bytes, EUI-64 8 bytes, or either one.
	GetPreferredLen() MACAddressLen
	// AllowsDashed allows addresses like "aa-bb-cc-dd-ee-ff".
	AllowsDashed() bool
	// AllowsSingleDashed allows addresses like "aabbcc-ddeeff".
	AllowsSingleDashed() bool
	// AllowsColonDelimited allows addresses like "aa:bb:cc:dd:ee:ff".
	AllowsColonDelimited() bool
	// AllowsDotted allows addresses like "aaa.bbb.ccc.ddd".
	AllowsDotted() bool
	// AllowsSpaceDelimited allows addresses like "aa bb cc dd ee ff".
	AllowsSpaceDelimited() bool
	// GetFormatParams returns the parameters that apply to formatting of the address segments.
	GetFormatParams() MACAddressStringFormatParams
}

type macAddressStringFormatParameters struct {
	addressStringFormatParameters
	noShortSegments bool
}

// AllowsShortSegments allows segments that are just a single hex digit and not two.
func (params *macAddressStringFormatParameters) AllowsShortSegments() bool {
	return !params.noShortSegments
}

// macAddressStringParameters has parameters for parsing MAC address strings.
// They are immutable and must be constructed using an IPAddressStringParamsBuilder.
type macAddressStringParameters struct {
	addressStringParameters
	formatParams          macAddressStringFormatParameters
	noAllowDashed         bool
	noAllowSingleDashed   bool
	noAllowColonDelimited bool
	noAllowDotted         bool
	noAllowSpaceDelimited bool
	allAddresses          MACAddressLen
}
