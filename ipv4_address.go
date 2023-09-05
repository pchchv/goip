package goip

const (
	IPv4SegmentSeparator      = '.'
	IPv4SegmentSeparatorStr   = "."
	IPv4BitsPerSegment        = 8
	IPv4BytesPerSegment       = 1
	IPv4SegmentCount          = 4
	IPv4ByteCount             = 4
	IPv4BitCount              = 32
	IPv4DefaultTextualRadix   = 10
	IPv4MaxValuePerSegment    = 0xff
	IPv4MaxValue              = 0xffffffff
	IPv4ReverseDnsSuffix      = ".in-addr.arpa"
	IPv4SegmentMaxChars       = 3
	ipv4BitsToSegmentBitshift = 3
)

var (
	zeroIPv4 = initZeroIPv4()
	ipv4All  = zeroIPv4.ToPrefixBlockLen(0)
)

// IPv4Address is an IPv4 address, or a subnet of multiple IPv4 addresses.
// An IPv4 address is composed of 4 1-byte segments and can optionally have an associated prefix length.
// Each segment can represent a single value or a range of values.
// The zero value is "0.0.0.0".
//
// To construct one from a string, use NewIPAddressString, then use the ToAddress or GetAddress method of [IPAddressString],
// and then use ToIPv4 to get an IPv4Address, assuming the string had an IPv4 format.
//
// For other inputs, use one of the multiple constructor functions like NewIPv4Address.
// You can also use one of the multiple constructors for [IPAddress] like NewIPAddress and then convert using ToIPv4.
type IPv4Address struct {
	ipAddressInternal
}

func (addr *IPv4Address) init() *IPv4Address {
	if addr.section == nil {
		return zeroIPv4
	}
	return addr
}

// ToPrefixBlockLen returns the subnet associated with the given prefix length.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block" for that prefix length.
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1.2.3.4" and the prefix length provided is 16, it returns the subnet "1.2.0.0/16", which can also be written as "1.2.*.*/16".
func (addr *IPv4Address) ToPrefixBlockLen(prefLen BitCount) *IPv4Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv4()
}

func newIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4()
}

func initZeroIPv4() *IPv4Address {
	div := zeroIPv4Seg
	segs := []*IPv4AddressSegment{div, div, div, div}
	section := NewIPv4Section(segs)
	return newIPv4Address(section)
}
