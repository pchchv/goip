package goip

import "github.com/pchchv/goip/address_error"

const (
	NoZone                           = ""
	IPv6SegmentSeparator             = ':'
	IPv6SegmentSeparatorStr          = ":"
	IPv6ZoneSeparator                = '%'
	IPv6ZoneSeparatorStr             = "%"
	IPv6AlternativeZoneSeparator     = '\u00a7'
	IPv6AlternativeZoneSeparatorStr  = "\u00a7" //'§'
	IPv6BitsPerSegment               = 16
	IPv6BytesPerSegment              = 2
	IPv6SegmentCount                 = 8
	IPv6MixedReplacedSegmentCount    = 2
	IPv6MixedOriginalSegmentCount    = 6
	IPv6MixedOriginalByteCount       = 12
	IPv6ByteCount                    = 16
	IPv6BitCount                     = 128
	IPv6DefaultTextualRadix          = 16
	IPv6MaxValuePerSegment           = 0xffff
	IPv6ReverseDnsSuffix             = ".ip6.arpa"
	IPv6ReverseDnsSuffixDeprecated   = ".ip6.int"
	IPv6UncSegmentSeparator          = '-'
	IPv6UncSegmentSeparatorStr       = "-"
	IPv6UncZoneSeparator             = 's'
	IPv6UncZoneSeparatorStr          = "s"
	IPv6UncRangeSeparator            = AlternativeRangeSeparator
	IPv6UncRangeSeparatorStr         = AlternativeRangeSeparatorStr
	IPv6UncSuffix                    = ".ipv6-literal.net"
	IPv6SegmentMaxChars              = 4
	ipv6BitsToSegmentBitshift        = 4
	IPv6AlternativeRangeSeparatorStr = AlternativeRangeSeparatorStr
)

var (
	zeroIPv6 = initZeroIPv6()
	ipv6All  = zeroIPv6.ToPrefixBlockLen(0)
)

// Zone represents an IPv6 address zone or scope.
type Zone string

// IsEmpty returns whether the zone is the zero-zone,
// which is the lack of a zone, or the empty string zone.
func (zone Zone) IsEmpty() bool {
	return zone == ""
}

// String implements the [fmt.Stringer] interface,
// returning the zone characters as a string
func (zone Zone) String() string {
	return string(zone)
}

// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.
// An IPv6 address is composed of 8 2-byte segments and can optionally have an associated prefix length.
// Each segment can represent a single value or a range of values.
// The zero value is "::".
//
// To construct one from a string, use NewIPAddressString, then use the ToAddress or GetAddress method of [IPAddressString],
// and then use ToIPv6 to get an IPv6Address, assuming the string had an IPv6 format.
//
// For other inputs, use one of the multiple constructor functions like NewIPv6Address.
// You can also use one of the multiple constructors for [IPAddress] like NewIPAddress and then convert using ToIPv6.
type IPv6Address struct {
	ipAddressInternal
}

func (addr *IPv6Address) init() *IPv6Address {
	if addr.section == nil {
		return zeroIPv6
	}
	return addr
}

// ToPrefixBlock returns the subnet associated with the prefix length of this address.
// If this address has no prefix length, this address is returned.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block".
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1:2:3:4:5:6:7:8/64" it returns the subnet "1:2:3:4::/64" which can also be written as "1:2:3:4:*:*:*:*/64".
func (addr *IPv6Address) ToPrefixBlock() *IPv6Address {
	return addr.init().toPrefixBlock().ToIPv6()
}

// ToPrefixBlockLen returns the subnet associated with the given prefix length.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block" for that prefix length.
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1:2:3:4:5:6:7:8" and the prefix length provided is 64, it returns the subnet "1:2:3:4::/64" which can also be written as "1:2:3:4:*:*:*:*/64".
func (addr *IPv6Address) ToPrefixBlockLen(prefLen BitCount) *IPv6Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv6()
}

// ToIP converts to an IPAddress, a polymorphic type usable with all IP addresses and subnets.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv6Address) ToIP() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(addr)
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToIPv6.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv6Address) ToAddressBase() *Address {
	return addr.ToIP().ToAddressBase()
}

func newIPv6Address(section *IPv6AddressSection) *IPv6Address {
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6()
}

func initZeroIPv6() *IPv6Address {
	div := zeroIPv6Seg
	segs := []*IPv6AddressSegment{div, div, div, div, div, div, div, div}
	section := NewIPv6Section(segs)
	return newIPv6Address(section)
}

func NewIPv6Address(section *IPv6AddressSection) (*IPv6Address, address_error.AddressValueError) {
	if section == nil {
		return zeroIPv6, nil
	}
	segCount := section.GetSegmentCount()
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6(), nil
}

func newIPv6AddressZoned(section *IPv6AddressSection, zone string) *IPv6Address {
	zoneVal := Zone(zone)
	result := createAddress(section.ToSectionBase(), zoneVal).ToIPv6()
	assignIPv6Cache(zoneVal, result.cache)
	return result
}

func assignIPv6Cache(zoneVal Zone, cache *addressCache) {
	if zoneVal != NoZone { // will need to cache its own strings
		cache.stringCache = &stringCache{ipv6StringCache: &ipv6StringCache{}, ipStringCache: &ipStringCache{}}
	}
}

// NewIPv6AddressFromBytes constructs an IPv6 address from the given byte slice.
// An error is returned when the byte slice has too many bytes to match the IPv6 segment count of 8.
// There should be 16 bytes or less, although extra leading zeros are tolerated.
func NewIPv6AddressFromBytes(bytes []byte) (addr *IPv6Address, err address_error.AddressValueError) {
	section, err := NewIPv6SectionFromSegmentedBytes(bytes, IPv6SegmentCount)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}
