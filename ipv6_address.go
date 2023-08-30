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

var zeroIPv6 = initZeroIPv6()

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
