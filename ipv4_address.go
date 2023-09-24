package goip

import (
	"math/big"
	"net"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

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

// ToIP converts to an IPAddress, a polymorphic type usable with all IP addresses and subnets.
// Afterwards, you can convert back with ToIPv4.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv4Address) ToIP() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(addr)
}

// Wrap wraps this IP address, returning a WrappedIPAddress, an implementation of ExtendedIPSegmentSeries,
// which can be used to write code that works with both IP addresses and IP address sections.
// Wrap can be called with a nil receiver, wrapping a nil address.
func (addr *IPv4Address) Wrap() WrappedIPAddress {
	return wrapIPAddress(addr.ToIP())
}

// WrapAddress wraps this IP address, returning a WrappedAddress, an implementation of ExtendedSegmentSeries,
// which can be used to write code that works with both addresses and address sections.
// WrapAddress can be called with a nil receiver, wrapping a nil address.
func (addr *IPv4Address) WrapAddress() WrappedAddress {
	return wrapAddress(addr.ToAddressBase())
}

// GetSection returns the backing section for this address or subnet, comprising all segments.
func (addr *IPv4Address) GetSection() *IPv4AddressSection {
	return addr.init().section.ToIPv4()
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToIPv4.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv4Address) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

// GetCount returns the count of addresses that this address or subnet represents.
//
// If just a single address, not a subnet of multiple addresses, returns 1.
//
// For instance, the IP address subnet "1.2.0.0/15" has the count of 2 to the power of 17.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *IPv4Address) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address, whether it is a subnet of multiple addresses.
func (addr *IPv4Address) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *IPv4Address) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// IsFullRange returns whether this address covers the entire IPv4 address space.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (addr *IPv4Address) IsFullRange() bool {
	return addr.GetSection().IsFullRange()
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

// NewIPv4AddressFromBytes constructs an IPv4 address from the given byte slice.
// An error is returned when the byte slice has too many bytes to match the IPv4 segment count of 4.
// There should be 4 bytes or less, although extra leading zeros are tolerated.
func NewIPv4AddressFromBytes(bytes []byte) (addr *IPv4Address, err address_error.AddressValueError) {
	if ipv4 := net.IP(bytes).To4(); ipv4 != nil {
		bytes = ipv4
	}
	section, err := NewIPv4SectionFromSegmentedBytes(bytes, IPv4SegmentCount)
	if err == nil {
		addr = newIPv4Address(section)
	}
	return
}
