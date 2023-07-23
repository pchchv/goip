package address_string_param

import "strings"

const (
	NoAddressOption        EmptyStrOption = "none"      // indicates that empty strings are not translated to addresses
	ZeroAddressOption      EmptyStrOption = ""          // is used by default, empty strings are translated to null addresses
	LoopbackOption         EmptyStrOption = "loopback"  // indicates that empty strings are translated to loopback addresses
	AllAddresses           AllStrOption   = ""          // default value, indicating that the all address string refers to all addresses of all IP versions
	AllPreferredIPVersion  AllStrOption   = "preferred" // indicates that the all address string refers to all addresses of the preferred IP version
	IPv4                   IPVersion      = "IPv4"      // represents Internet Protocol version 4
	IPv6                   IPVersion      = "IPv6"      // represents Internet Protocol version 6
	IndeterminateIPVersion IPVersion      = ""          // represents an unspecified IP address version
)

var (
	_                     IPAddressStringParams   = &ipAddressStringParameters{}
	_                     IPv6AddressStringParams = &ipv6AddressStringParameters{}
	_                     IPv4AddressStringParams = &ipv4AddressStringParameters{}
	defaultEmbeddedParams *ipAddressStringParameters
)

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

// IPv6AddressStringParams provides parameters specific to IPv6 addresses and subnets.
type IPv6AddressStringParams interface {
	IPAddressStringFormatParams
	// AllowsMixed allows mixed-in embedded IPv4 like "a:b:c:d:e:f:1.2.3.4".
	AllowsMixed() bool
	// AllowsZone allows zones like "a:b:c:d:e:f:a:b%zone".
	AllowsZone() bool
	// AllowsEmptyZone allows the zone character % with no following zone.
	AllowsEmptyZone() bool
	// AllowsBase85 allows IPv6 single-segment base 85 addresses.
	AllowsBase85() bool
	// GetMixedParams provides the IP parameters that for parsing the embedded IPv4 section of a mixed IPv6/v4 address, if AllowsMixed is true.
	GetMixedParams() IPAddressStringParams
	// GetEmbeddedIPv4AddressParams returns the IPv4 parameters for parsing the embedded IPv4 section of a mixed IPv6/v4 address.
	GetEmbeddedIPv4AddressParams() IPv4AddressStringParams
}

// IPAddressStringParams provides parameters for parsing IP address strings,
// specifying what to allow, what to disallow, and other options.
// This allows to control the validation performed by IPAddressString.
// IPAddressString uses the default permissive IPAddressStringParams instance if one is not specified.
// If you want to use parameters other than the default, use this interface.
// Immutable instances can be built using the IPAddressStringParamsBuilder.
type IPAddressStringParams interface {
	AddressStringParams
	// AllowsPrefix indicates whether addresses with prefix length like 1.2.0.0/16 are allowed.
	AllowsPrefix() bool
	// EmptyStrParsedAs determines how a zero-length empty string is translated to an address.
	// If the option is ZeroAddressOption or LoopbackOption, then if defers to GetPreferredVersion() for the version.
	EmptyStrParsedAs() EmptyStrOption
	// AllStrParsedAs determines how the "all" string "*" is translated to addresses.
	// If the option is AllPreferredIPVersion, then it defers to GetPreferredVersion() for the version.
	AllStrParsedAs() AllStrOption
	// AllowsMask allows masks to follow valid addresses, such as 1.2.3.4/255.255.0.0 which has the mask 255.255.0.0
	// If the mask is the mask for a network prefix length, this is interpreted as the subnet for that network prefix length.
	// Otherwise the address is simply masked by the mask.
	// For instance, 1.2.3.4/255.0.255.0 is 1.0.3.0, while 1.2.3.4/255.255.0.0 is 1.2.0.0/16.
	AllowsMask() bool
	// GetPreferredVersion indicates the version to use for ambiguous addresses strings,
	// like prefix lengths less than 32 bits which are translated to masks,
	// the "all" address or the "empty" address.
	// The default is IPv6.
	// If either of AllowsIPv4() or AllowsIPv6() returns false, then those settings take precedence over this setting.
	GetPreferredVersion() IPVersion
	// AllowsIPv4 allows IPv4 addresses and subnets.
	AllowsIPv4() bool
	// AllowsIPv6 allows IPv6 addresses and subnets.
	AllowsIPv6() bool
	// GetIPv4Params returns the parameters that apply specifically to IPv4 addresses and subnets.
	GetIPv4Params() IPv4AddressStringParams
	// GetIPv6Params returns the parameters that apply specifically to IPv6 addresses and subnets.
	GetIPv6Params() IPv6AddressStringParams
}

// IPAddressStringFormatParamsBuilder builds an immutable IPAddressStringFormatParams for controlling parsing of IP address strings.
type IPAddressStringFormatParamsBuilder struct {
	AddressStringFormatParamsBuilder
	ipParams ipAddressStringFormatParameters
	parent   *IPAddressStringParamsBuilder
}

// GetParentBuilder returns the original IPAddressStringParamsBuilder builder that this was obtained from,
// if this builder was obtained from a IPAddressStringParamsBuilder.
func (builder *IPAddressStringFormatParamsBuilder) GetParentBuilder() *IPAddressStringParamsBuilder {
	return builder.parent
}

// ToParams returns an immutable IPAddressStringFormatParams instance built by this builder
func (builder *IPAddressStringFormatParamsBuilder) ToParams() IPAddressStringFormatParams {
	result := &builder.ipParams
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

func (builder *IPAddressStringFormatParamsBuilder) set(params IPAddressStringFormatParams) {
	if p, ok := params.(*ipAddressStringFormatParameters); ok {
		builder.ipParams = *p
	} else {
		builder.ipParams = ipAddressStringFormatParameters{
			allowPrefixesBeyondAddrSize: params.AllowsPrefixesBeyondAddressSize(),
			noPrefixLengthLeadingZeros:  !params.AllowsPrefixLenLeadingZeros(),
			noBinary:                    !params.AllowsBinary(),
		}
	}
	builder.AddressStringFormatParamsBuilder.set(params)
}

type IPv6AddressStringParamsBuilder struct {
	// This is not anonymous since it clashes with IPAddressStringFormatParamsBuilder,
	// both have ipAddressStringFormatParameters and AddressStringFormatParams
	// and thee builder IPAddressStringFormatParamsBuilder takes precedence
	params          ipv6AddressStringParameters
	embeddedBuilder *IPAddressStringParamsBuilder
	IPAddressStringFormatParamsBuilder
}

// IPv4AddressStringParamsBuilder builds an immutable IPv4AddressStringParams for controlling parsing of IPv4 address strings.
type IPv4AddressStringParamsBuilder struct {
	IPAddressStringFormatParamsBuilder
	params      ipv4AddressStringParameters
	mixedParent *IPv6AddressStringParamsBuilder
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

// IsIndeterminate returns true if this represents an unspecified IP address version.
func (version IPVersion) IsIndeterminate() bool {
	if len(version) == 4 {
		dig := version[3]
		return (dig != '4' && dig != '6') || !strings.EqualFold(string(version[:3]), "IPv")
	}
	return true
}

// String returns "IPv4", "IPv6", or the zero-value "" representing an indeterminate version.
func (version IPVersion) String() string {
	return string(version)
}

type ipv6AddressStringParameters struct {
	ipAddressStringFormatParameters
	noMixed, noZone, noBase85, noEmptyZone bool
	embeddedParams                         *ipAddressStringParameters
}

// AllowsMixed allows mixed-in embedded IPv4 like "a:b:c:d:e:f:1.2.3.4".
func (params *ipv6AddressStringParameters) AllowsMixed() bool {
	return !params.noMixed
}

// AllowsZone allows zones like "a:b:c:d:e:f:a:b%zone".
func (params *ipv6AddressStringParameters) AllowsZone() bool {
	return !params.noZone
}

// AllowsEmptyZone allows the zone character % with no following zone'
func (params *ipv6AddressStringParameters) AllowsEmptyZone() bool {
	return !params.noEmptyZone
}

// AllowsBase85 allows IPv6 single-segment base 85 addresses
func (params *ipv6AddressStringParameters) AllowsBase85() bool {
	return !params.noBase85
}

// GetMixedParams provides the parameters that for parsing the embedded IPv4 section of a mixed IPv6/v4 address, if AllowsMixed is true'
func (params *ipv6AddressStringParameters) GetMixedParams() IPAddressStringParams {
	result := params.embeddedParams
	if result == nil {
		result = defaultEmbeddedParams
	}
	return result
}

// GetEmbeddedIPv4AddressParams returns the IPv4 parameters for parsing the embedded IPv4 section of a mixed IPv6/v4 address'
func (params *ipv6AddressStringParameters) GetEmbeddedIPv4AddressParams() IPv4AddressStringParams {
	return params.embeddedParams.GetIPv4Params()
}

// ipAddressStringParameters has parameters for parsing IP address strings.
// They are immutable and can be constructed using an IPAddressStringParamsBuilder.
type ipAddressStringParameters struct {
	addressStringParameters
	ipv4Params        ipv4AddressStringParameters
	ipv6Params        ipv6AddressStringParameters
	emptyStringOption EmptyStrOption
	allStringOption   AllStrOption
	preferredVersion  IPVersion
	noPrefix          bool
	noMask            bool
	noIPv6            bool
	noIPv4            bool
}

// AllowsPrefix indicates whether addresses with prefix length like 1.2.0.0/16 are allowed.
func (params *ipAddressStringParameters) AllowsPrefix() bool {
	return !params.noPrefix
}

// EmptyStrParsedAs determines how a zero-length empty string is translated to an address.
// If the option is ZeroAddressOption or LoopbackOption, then if defers to GetPreferredVersion() for the version.
func (params *ipAddressStringParameters) EmptyStrParsedAs() EmptyStrOption {
	return params.emptyStringOption
}

// AllStrParsedAs determines how the "all" string "*" is translated to addresses.
// If the option is AllPreferredIPVersion, then it defers to GetPreferredVersion() for the version.
func (params *ipAddressStringParameters) AllStrParsedAs() AllStrOption {
	return params.allStringOption
}

// GetPreferredVersion indicates the version to use for ambiguous addresses strings,
// like prefix lengths less than 32 bits which are translated to masks,
// the "all" address or the "empty" address.
// The default is IPv6.
// If either of AllowsIPv4() or AllowsIPv6() returns false,
// then those settings take precedence over this setting.
func (params *ipAddressStringParameters) GetPreferredVersion() IPVersion {
	return params.preferredVersion
}

// AllowsMask allows masks to follow valid addresses, such as 1.2.3.4/255.255.0.0 which has the mask 255.255.0.0
// If the mask is the mask for a network prefix length, this is interpreted as the subnet for that network prefix length.
// Otherwise the address is simply masked by the mask.
// For instance, 1.2.3.4/255.0.255.0 is 1.0.3.0, while 1.2.3.4/255.255.0.0 is 1.2.0.0/16.
func (params *ipAddressStringParameters) AllowsMask() bool {
	return !params.noMask
}

// AllowsIPv4 allows IPv4 addresses and subnets.
func (params *ipAddressStringParameters) AllowsIPv4() bool {
	return !params.noIPv4
}

// AllowsIPv6 allows IPv6 addresses and subnets.
func (params *ipAddressStringParameters) AllowsIPv6() bool {
	return !params.noIPv6
}

// GetIPv4Params returns the parameters that apply specifically to IPv4 addresses and subnets.
func (params *ipAddressStringParameters) GetIPv4Params() IPv4AddressStringParams {
	return &params.ipv4Params
}

// GetIPv6Params returns the parameters that apply specifically to IPv6 addresses and subnets.
func (params *ipAddressStringParameters) GetIPv6Params() IPv6AddressStringParams {
	return &params.ipv6Params
}

// IPAddressStringParamsBuilder builds an immutable IPAddressStringParameters for controlling parsing of IP address strings.
type IPAddressStringParamsBuilder struct {
	params ipAddressStringParameters
	AddressStringParamsBuilder
	ipv4Builder IPv4AddressStringParamsBuilder
	ipv6Builder IPv6AddressStringParamsBuilder
	parent *HostNameParamsBuilder
}
