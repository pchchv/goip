package goip

const (
	HexPrefix                       = "0x"
	OctalPrefix                     = "0"
	BinaryPrefix                    = "0b"
	RangeSeparator                  = '-'
	RangeSeparatorStr               = "-"
	AlternativeRangeSeparator       = '\u00bb'
	AlternativeRangeSeparatorStr    = "\u00bb" // '»'
	ExtendedDigitsRangeSeparatorStr = AlternativeRangeSeparatorStr
	SegmentWildcard                 = '*'
	SegmentWildcardStr              = "*"
	SegmentSqlWildcard              = '%'
	SegmentSqlWildcardStr           = "%"
	SegmentSqlSingleWildcard        = '_'
	SegmentSqlSingleWildcardStr     = "_"
)

var segmentWildcardStr = SegmentWildcardStr

// SegmentValueProvider provides values for segments.
// Values that fall outside the segment value type range will be truncated using standard golang integer type conversions.
type SegmentValueProvider func(segmentIndex int) SegInt

// AddressValueProvider provides values for addresses.
type AddressValueProvider interface {
	GetSegmentCount() int
	GetValues() SegmentValueProvider
	GetUpperValues() SegmentValueProvider
}

// identifierStr is a string representation of an address or host name.
type identifierStr struct {
	idStr HostIdentifierString // MACAddressString or IPAddressString or HostName
}

type addrsCache struct {
	lower *Address
	upper *Address
}

type addressCache struct {
	addrsCache    *addrsCache
	stringCache   *stringCache // only used by IPv6 when there is a zone
	identifierStr *identifierStr
}

type addressInternal struct {
	section *AddressSection
	zone    Zone
	cache   *addressCache
}

// Address represents a single address or a set of multiple addresses, such as an IP subnet or a set of MAC addresses.
//
// Addresses consist of a sequence of segments, each with the same bit-size.
// The number of such segments and the bit-size are determined by the underlying version or type of address, whether IPv4, IPv6, MAC, or other.
// Each segment can represent a single value or a sequential range of values.
// Addresses can also have an appropriate prefix length - the number of consecutive bits that make up the prefix, the most significant bits of the address.
//
// To create an address from a string, use NewIPAddressString or NewMACAddressString,
// then use the ToAddress or GetAddress methods to get [IPAddress] or [MACAddress] and then you can convert it to that type using the ToAddressBase method.
//
// Any specific address types can be converted to Address using the ToAddressBase method
// and then returned to the original types using methods such as ToIPv6, ToIP, ToIPv4 and ToMAC.
// When such a method is called for a given address,
// if the address was not originally constructed as the type returned by the method, the method will return nil.
// Conversion methods work with nil pointers (return nil), so they can be safely chained together.
//
// This allows you to create polymorphic code that works with all addresses, like the address triplet code in this library,
// while at the same time allowing methods and code specific to each version or address type.
//
// You can also use the IsIPv6, IsIP, IsIPv4 and IsMAC methods,
// which will return true if and only if the corresponding ToIPv6, ToIP, ToIPv4 and ToMAC methods return non-nil, respectively.
//
// A zero value for an address is an address with no segments and no associated version or type of address, also known as adaptive zero.
type Address struct {
	addressInternal
}
