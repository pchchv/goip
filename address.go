package goip

import "math/big"

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

func createAddress(section *AddressSection, zone Zone) *Address {
	res := &Address{
		addressInternal{
			section: section,
			zone:    zone,
			cache:   &addressCache{},
		},
	}
	return res
}

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

// GetBitCount returns the number of bits that make up a given address,
// or each address in the range if a subnet.
func (addr *addressInternal) GetBitCount() BitCount {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetBitCount()
}

// GetByteCount returns the number of bytes required for a given address,
// or each address in the range if a subnet.
func (addr *addressInternal) GetByteCount() int {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetByteCount()
}

// GetPrefixCount returns the number of prefixes in a given address or subnet.
// The prefix length is given by GetPrefixLen.
// If the prefix length is not nil, a count of the range of values in the prefix is returned.
// If the prefix length is nil, the same value is returned as in GetCount.
func (addr *addressInternal) GetPrefixCount() *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetPrefixCount()
}

// GetPrefixCountLen returns the number of prefixes in the given address or subnet for the given prefix length.
// If it is not a subnet with multiple addresses or a subnet with a single prefix of the given prefix length, 1 is returned.
func (addr *addressInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetPrefixCountLen(prefixLen)
}

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
func (addr *addressInternal) GetBlockCount(segments int) *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetBlockCount(segments)
}

// GetPrefixLen returns the prefix length or nil if there is no prefix.
//
// A prefix length indicates the number of bits in the initial part (high significant bits) of the address that make up the prefix.
//
// A prefix is a part of the address that is not specific to that address but common amongst a group of addresses, such as a CIDR prefix block subnet.
//
// For IP addresses, the prefix is explicitly specified when the address is created.
// For example, "1.2.0.0.0/16" has a prefix length of 16, and "1.2.*.*" has no prefix length,
// although both represent the same set of addresses and are considered the same.
// Prefixes may be considered variable for a given IP address and may depend on routing.
//
// The GetMinPrefixLenForBlock and GetPrefixLenForSingleBlock methods help you obtain or determine the length of a prefix if one does not already exist.
// The ToPrefixBlockLen method allows you to create a subnet consisting of a block of addresses for any given prefix length.
//
// For MAC addresses, the prefix is initially derived from a range, so "1:2:3:*:*:*" has a prefix length of 24.
// MAC addresses derived from an address with a prefix length can retain the prefix length regardless of their own range of values.
func (addr *addressInternal) GetPrefixLen() PrefixLen {
	return addr.getPrefixLen().copy()
}

// IsSequential returns whether the given address or subnet represents a range of addresses that are sequential.
//
// In the general case for a subnet, this means that any segment that spans a range of values must be followed by segments that are full range and span all values.
//
// Individual addresses are sequential and CIDR prefix blocks are sequential.
// The "1.2.3-4.5" subnet is not sequential because the two addresses it represents, "1.2.3.5" and "1.2.4.5", are not ("1.2.3.6" is in between but not part of the subnet).
//
// Given any subnet of IP addresses, you can use the SequentialBlockIterator to convert any subnet into a set of sequential subnets.
func (addr *addressInternal) IsSequential() bool {
	section := addr.section
	if section == nil {
		return true
	}
	return section.IsSequential()
}

func (addr *addressInternal) getCount() *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetCount()
}

func (addr *addressInternal) getPrefixLen() PrefixLen {
	if addr.section == nil {
		return nil
	}
	return addr.section.getPrefixLen()
}

// isMultiple returns true if this address represents more than single individual address, whether it is a subnet of multiple addresses.
func (addr *addressInternal) isMultiple() bool {
	return addr.section != nil && addr.section.isMultiple()
}

// isPrefixed returns whether the given address has an associated prefix length.
func (addr *addressInternal) isPrefixed() bool {
	return addr.section != nil && addr.section.IsPrefixed()
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
