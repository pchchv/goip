package address_string_param

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
