package address_string_param

import "strings"

const (
	NoAddressOption       EmptyStrOption = "none"      // indicates that empty strings are not translated to addresses
	ZeroAddressOption     EmptyStrOption = ""          // is used by default, empty strings are translated to null addresses
	LoopbackOption        EmptyStrOption = "loopback"  // indicates that empty strings are translated to loopback addresses
	AllAddresses          AllStrOption   = ""          // default value, indicating that the all address string refers to all addresses of all IP versions
	AllPreferredIPVersion AllStrOption   = "preferred" // indicates that the all address string refers to all addresses of the preferred IP version
	IPv4                  IPVersion      = "IPv4"      // represents Internet Protocol version 4
	IPv6                  IPVersion      = "IPv6"      // represents Internet Protocol version 6
)

var _ IPv4AddressStringParams = &ipv4AddressStringParameters{}

type ipAddressStringFormatParameters struct {
	addressStringFormatParameters
	allowPrefixesBeyondAddrSize,
	noPrefixLengthLeadingZeros,
	noBinary bool
}

// AllowsPrefixesBeyondAddressSize allows prefix length values greater than 32 for IPv4 or greater than 128 for IPv6.
func (params *ipAddressStringFormatParameters) AllowsPrefixesBeyondAddressSize() bool {
	return params.allowPrefixesBeyondAddrSize
}

// AllowsPrefixLenLeadingZeros allows leading zeros in the prefix length like "1.2.3.4/016".
func (params *ipAddressStringFormatParameters) AllowsPrefixLenLeadingZeros() bool {
	return !params.noPrefixLengthLeadingZeros
}

// AllowsBinary allows binary addresses like "11111111.0.1.0" or "1111111111111111::".
func (params *ipAddressStringFormatParameters) AllowsBinary() bool {
	return !params.noBinary
}

type ipv4AddressStringParameters struct {
	ipAddressStringFormatParameters
	no_inet_aton_hex,
	no_inet_aton_octal,
	no_inet_aton_joinedSegments,
	inet_aton_single_segment_mask,
	no_inet_aton_leading_zeros bool
}

// AllowsInetAtonHex allows IPv4 inet_aton hexadecimal format "0xa.0xb.0xc.0cd".
func (params *ipv4AddressStringParameters) AllowsInetAtonHex() bool {
	return !params.no_inet_aton_hex
}

// AllowsInetAtonOctal allows octal IPv4 inet_aton format, an example would be "04.05.06.07".
// Can be overridden by the AllowLeadingZeros.
func (params *ipv4AddressStringParameters) AllowsInetAtonOctal() bool {
	return !params.no_inet_aton_octal
}

// AllowsInetAtonJoinedSegments allows IPv4 joined segments like "1.2.3", "1.2', or just "1".
// For the case of just 1 segment, the behaviour is controlled by allowSingleSegment
func (params *ipv4AddressStringParameters) AllowsInetAtonJoinedSegments() bool {
	return !params.no_inet_aton_joinedSegments
}

// AllowsInetAtonSingleSegmentMask specifies whether to allow
// a mask that looks like the prefix length: "1.2.3.5/255" when resolving merged IPv4 segments.
func (params *ipv4AddressStringParameters) AllowsInetAtonSingleSegmentMask() bool {
	return params.inet_aton_single_segment_mask
}

// AllowsInetAtonLeadingZeros allows a hexadecimal or octal IPv4 inet_aton to have leading zeros, such as in the first two segments "0x0a.00b.c.d".
// The first 0 is not considered a leading zero, it denotes either an octal or hexadecimal number depending on whether it is followed by an 'x'.
// Zeros that appear afterwards are inet_aton leading zeros.
func (params *ipv4AddressStringParameters) AllowsInetAtonLeadingZeros() bool {
	return !params.no_inet_aton_leading_zeros
}

// EmptyStrOption - an option specifying how to convert an empty address string to an address.
type EmptyStrOption string

// AllStrOption - an option specifying how to convert an all address string, such as "*", to an address.
type AllStrOption string

// IPAddressStringFormatParams provides format parameters that apply to all IP addresses, but may be different for IPv4 or IPv6,
// allowing you to account for cases where you need to allow something for one version and not the other.
type IPAddressStringFormatParams interface {
	AddressStringFormatParams
	// AllowsPrefixesBeyondAddressSize allows prefix length values greater than 32 for IPv4 or greater than 128 for IPv6.
	AllowsPrefixesBeyondAddressSize() bool
	// AllowsPrefixLenLeadingZeros allows leading zeros in the prefix length like "1.2.3.4/016".
	AllowsPrefixLenLeadingZeros() bool
	// AllowsBinary allows binary addresses like "11111111.0.1.0" or "1111111111111111::".
	AllowsBinary() bool
}

// IPv4AddressStringParams provides parameters specific to IPv4 addresses and subnets
type IPv4AddressStringParams interface {
	IPAddressStringFormatParams
	// AllowsInetAtonHex allows IPv4 inet_aton hexadecimal format "0xa.0xb.0xc.0cd".
	AllowsInetAtonHex() bool
	// AllowsInetAtonOctal allows IPv4 inet_aton octal format, "04.05.06.07" being an example.
	// Can be overridden by allowLeadingZeros
	AllowsInetAtonOctal() bool
	// AllowsInetAtonJoinedSegments allows IPv4 joined segments like "1.2.3", "1.2", or just "1".
	// For the case of just 1 segment, the behaviour is controlled by allowSingleSegment.
	AllowsInetAtonJoinedSegments() bool
	// AllowsInetAtonSingleSegmentMask indicates whether you allow a mask that looks like a prefix length when you allow IPv4 joined segments: "1.2.3.5/255".
	AllowsInetAtonSingleSegmentMask() bool
	// AllowsInetAtonLeadingZeros allows IPv4 inet_aton hexadecimal or octal to have leading zeros, such as in the first two segments of "0x0a.00b.c.d".
	// The first 0 is not considered a leading zero, it either denotes octal or hex depending on whether it is followed by an 'x'.
	// Zeros that appear afterwards are inet_aton leading zeros.
	AllowsInetAtonLeadingZeros() bool
}

// IPVersion is the version type used by IP string parameters.
// It is interchangeable with ipaddr.Version,
// a more generic version type used by the library as a whole.
type IPVersion string

// IsIPv6 returns true if this represents version 6.
func (version IPVersion) IsIPv6() bool {
	return strings.EqualFold(string(version), string(IPv6))
}

// IsIPv4 returns true if this represents version 4.
func (version IPVersion) IsIPv4() bool {
	return strings.EqualFold(string(version), string(IPv4))
}
