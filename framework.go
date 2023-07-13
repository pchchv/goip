package goip

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"

	"github.com/pchchv/goip/address_error"
)

// AddressComponent represents all addresses, address sections and address segments.
type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	// TestBit returns true if the bit in the lowest value of the address component by the given index is 1,
	// where index 0 refers to the lowest significant bit. In other words, it calculates (bits & (1 << n) != 0),
	// using the lowest value of this address component. TestBit panics if n < 0,
	// or if it matches or exceeds the number of bits of this address component.
	TestBit(index BitCount) bool
	// IsOneBit returns true if the bit in the lowest value of this address component by the given index is 1, where index 0 refers to the highest bit.
	// IsOneBit causes a panic if bitIndex is less than zero, or if it is greater than the number of bits of this address component.
	IsOneBit(index BitCount) bool
	// ToHexString writes this address component as a single hex value
	// (possibly two values if the range is not a prefix block),
	// the number of digits according to the number of bits,
	// with or without the preceding "0x" prefix.
	// If a multi-digit component cannot be written as a single prefix block or
	// a range of two values, an error is returned.
	ToHexString(with0xPrefix bool) (string, address_error.IncompatibleAddressError)
	// ToNormalizedString creates a string that is consistent for
	// all address components of the same type and version.
	ToNormalizedString() string
}

// AddressItem represents all addresses, division groups,
// divisions and consecutive ranges.
// Any address item can be compared to any other.
type AddressItem interface {
	BitItem
	// GetValue returns the smallest individual address element in the range of address elements as an integer value.
	GetValue() *big.Int
	// GetUpperValue returns the topmost individual address element in the range of address elements as an integer value.
	GetUpperValue() *big.Int
	// CopyBytes copies the value of the smallest single address element in that address element range to a byte fragment.
	// If the value can fit in a given fragment,
	// the value is copied to that fragment and a length-adjusted subfragment is returned.
	// Otherwise a new fragment is created and returned with the value.
	CopyBytes(bytes []byte) []byte
	// CopyUpperBytes copies the value of the oldest single address element in that address element range to a byte fragment.
	// If the value can fit in a given fragment,
	// the value is copied to that fragment and a length-adjusted subfragment is returned.
	// Otherwise a new fragment is created and returned with the value.
	CopyUpperBytes(bytes []byte) []byte
	// Bytes returns the smallest single address element in the range of address elements as a byte fragment.
	Bytes() []byte
	// UpperBytes returns the topmost individual address element in the range of address elements as a byte slice.
	UpperBytes() []byte
	// GetCount provides the number of address items represented by the AddressItem, such as subnet size for IP addresses.
	GetCount() *big.Int
	// IsMultiple returns whether the given element represents multiple values (a count greater than 1).
	IsMultiple() bool
	// IsFullRange returns whether the given address element represents
	// all possible values reachable by an address element of that type.
	// This is true if and only if both IncludesZero and IncludesMax return true.
	IsFullRange() bool
	// IncludesZero returns whether the item includes a value of zero in its range.
	IncludesZero() bool
	// IncludesMax returns whether the item includes the maximum value,
	// a value whose bits are all one, in its range.
	IncludesMax() bool
	// IsZero returns whether the given address element is exactly zero.
	IsZero() bool
	// IsMax returns whether the given address element corresponds exactly to the maximum possible value - a value whose bits are all one.
	IsMax() bool
	// ContainsPrefixBlock returns whether the values of a given element contain a prefix block for a given prefix length.
	// Unlike ContainsSinglePrefixBlock, the presence of multiple prefix values for a given prefix length is irrelevant.
	ContainsPrefixBlock(BitCount) bool
	// ContainsSinglePrefixBlock returns whether the values of this series contain a single prefix block for a given prefix length.
	// This means that this element has only one prefix of a given length,
	// and this element contains a prefix block for that prefix, all elements with the same prefix.
	ContainsSinglePrefixBlock(BitCount) bool
	// GetPrefixLenForSingleBlock returns the prefix length for which there is only one prefix of that length in the given element,
	// and the range of that element matches the block of all values for that prefix.
	// If the whole range can be described this way, this method returns the same value as GetMinPrefixLenForBlock.
	// If no such prefix length exists, it returns nil.
	// If this element represents a single value, the number of bits is returned.
	GetPrefixLenForSingleBlock() PrefixLen
	// GetMinPrefixLenForBlock returns the smallest possible prefix length such that this element includes a block of all values for that prefix length.
	// If the entire range can be defined in this way, this method returns the same value as GetPrefixLenForSingleBlock.
	// This item can have a single prefix or multiple possible prefix values for the returned prefix length.
	// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values. If this element represents a single value, the number of bits is returned.
	GetMinPrefixLenForBlock() BitCount
	// GetPrefixCountLen returns the count of the number of distinct values within the prefix part of the range of values for this item
	GetPrefixCountLen(BitCount) *big.Int
	// Compare returns a negative integer, zero, or a positive integer if the given address element is less than,
	// equal to, or greater than the given element.
	// Any address element is comparable to any other address element.
	// All address elements use CountComparator for comparison.
	Compare(AddressItem) int
	// CompareSize compares the number of two address elements, whether they are addresses in a subnet or address range,
	// whether they are individual sections in a collection of sections, whether they are individual segments in a segment range.
	// It compares the number of individual elements within each.
	// Instead of counting the number with GetCount,
	// it can use more efficient ways to determine whether one element represents more individual addresses than another.
	// CompareSize returns a positive integer if the given element has a larger count than the given one,
	// zero if they are the same, or a negative integer if the other element has a larger count.
	CompareSize(AddressItem) int
	fmt.Stringer
	fmt.Formatter
}

type BitItem interface {
	// GetByteCount returns the number of bytes needed
	// for each value that makes up the given address element,
	// rounded up if the number of bits is not a multiple of 8.
	GetByteCount() int
	// GetBitCount returns the number of bits in each value comprising this address item.
	GetBitCount() BitCount
}

type Prefixed interface {
	// IsPrefixed returns whether the given element has a prefix length associated with it.
	IsPrefixed() bool
	// GetPrefixLen returns the prefix length, or nil if there is no prefix length.
	// The prefix length indicates the number of bits in the initial part (the most significant bits) of the series that make up the prefix.
	// A prefix is a portion of a series that is not specific to that series but is common to the group, such as a subnet of a CIDR prefix block.
	GetPrefixLen() PrefixLen
	// IsPrefixBlock returns whether the given element has a prefix length and whether it includes the block associated with that prefix length.
	// If the prefix length is the same as the number of bits, true is returned.
	// This method differs from ContainsPrefixBlock in that it returns false if
	// the given element has no prefix length or has a prefix length different from
	// the prefix length for which ContainsPrefixBlock returns true.
	IsPrefixBlock() bool
	// IsSinglePrefixBlock returns whether the value range matches one subnet block for the prefix length.
	// This method differs from ContainsSinglePrefixBlock in that it returns false if the given series
	// has no prefix length or a different prefix length than the prefix length for which ContainsSinglePrefixBlock returns true.
	IsSinglePrefixBlock() bool
}

// HostIdentifierString represents a string that is used to identify a host.
type HostIdentifierString interface {
	ToNormalizedString() string     // ToNormalizedString provides a normalized String representation for the host identified by this HostIdentifierString instance
	IsValid() bool                  // IsValid returns whether the wrapped string is a valid identifier for the host
	Wrap() ExtendedIdentifierString // Wrap wraps an identifier string into an extended type that is polymorphic to other identifier strings
	fmt.Stringer
	fmt.Formatter
}

// AddressDivisionSeries serves as a common interface for all division groups, address sections and addresses.
type AddressDivisionSeries interface {
	AddressItem
	GetDivisionCount() int                    // GetDivisionCount returns the number of divisions
	GetBlockCount(divisionCount int) *big.Int // GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments
	// GetPrefixCount returns the count of prefixes in this series for its prefix length, or the total count if it has no prefix length
	GetPrefixCount() *big.Int
	// GetSequentialBlockCount provides a count of elements from the sequential block iterator,
	// the minimum number of sequential address division series that constitute a given division series.
	GetSequentialBlockCount() *big.Int
	// GetSequentialBlockIndex gets the minimum division index for which all subsequent divisions are full-range blocks.
	// A division by this index is not a full-range block if all divisions are not full-range.
	// A division by this index and all subsequent divisions form a consecutive row.
	// For a full range to be consecutive, the preceding divisions must be single-valued.
	GetSequentialBlockIndex() int
	// IsSequential returns whether the series represents a range of values that are consistent.
	// Generally, this means that any division spanning a range of values must be followed by divisions that are complete, covering all values.
	IsSequential() bool
	Prefixed
	// GetGenericDivision returns the division by the given index as DivisionType.
	// The first division is at index 0.
	// GetGenericDivision panics when the index is negative or an index greater than the number of divisions.
	// Useful for comparisons.
	GetGenericDivision(index int) DivisionType
}

// StandardDivGroupingType represents any standard division grouping
// (division groupings or address sections where all divisions are 64 bits or less)
// including [AddressSection], [IPAddressSection], [IPv4AddressSection], [IPv6AddressSection], [MACAddressSection] and [AddressDivisionGrouping].
type StandardDivGroupingType interface {
	AddressDivisionSeries
	// IsAdaptiveZero returns true if the division grouping was originally created as an implicitly zero-valued division or grouping
	// (e.g., IPv4AddressSection{}),
	// that is, it was not constructed with the constructor function.
	// Such a grouping with no divisions or segments is converted to an implicit zero-valued grouping of any type or version, be it IPv6, IPv4, MAC, or other.
	// In other words, when a section or grouping is a zero-value, it is equivalent and convertible to the zero value of any other section or grouping.
	IsAdaptiveZero() bool
	// ToDivGrouping converts to AddressDivisionGrouping, a polymorphic type used with all address sections and division groupings.
	// Implementations of ToDivGrouping can be called with a nil receiver, allowing this method to be used in a chain with methods that can return a nil pointer.
	ToDivGrouping() *AddressDivisionGrouping
}

// AddressSectionType represents any address section that can be converted to/from a basic AddressSection type,
// including [AddressSection], [IPAddressSection], [IPv4AddressSection], [IPv6AddressSection] and [MACAddressSection].
type AddressSectionType interface {
	StandardDivGroupingType
	// Equal returns whether the given address section is equal to this address section.
	// Two address sections are equal if they represent the same set of sections.
	// They must match:
	//  - type/version (IPv4, IPv6, MAC, etc.)
	//  - segment counts
	//  - bits per segment
	//  - segment value ranges
	// Prefix lengths are ignored.
	Equal(AddressSectionType) bool
	// Contains returns whether the given address is the same type and version as the given address section,
	// and whether it contains all the values in the given section.
	// Sections must also have the same number of segments to be comparable, otherwise false is returned.
	Contains(AddressSectionType) bool
	// PrefixEqual determines whether the given section matches this section to the prefix length of that section.
	// It returns whether the argument section has the same address section prefix values as this section.
	// The entire prefix of a given section must be present in the other section for comparison.
	PrefixEqual(AddressSectionType) bool
	// PrefixContains returns whether the prefix values in a given address section are prefix values in that address section using the prefix length of that section.
	// If this address section has no prefix length, the entire address is compared.
	// Returns whether the prefix of a given address contains all values of the same prefix length in that address.
	// All prefix bits of a given section must be present in the other section for comparison.
	PrefixContains(AddressSectionType) bool
	// ToSectionBase converts to AddressSection, a polymorphic type used with all address sections.
	// Implementations of ToSectionBase can be called with a nil receiver,
	// allowing this method to be used in a chain with methods that can return a nil pointer.
	ToSectionBase() *AddressSection
}

// IPAddressRange represents all instances of IPAddress and all instances of a sequential IPAddress range.
type IPAddressRange interface {
	// GetIPVersion returns the IP version of this IP address range
	GetIPVersion() IPVersion
	// GetLowerIPAddress returns the address in the subnet or address range with
	// the lowest numeric value that will be the receiver if it represents a single address.
	// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
	GetLowerIPAddress() *IPAddress
	// GetUpperIPAddress returns the address in the subnet or address range with
	// the largest numeric value that will be the receiver if it represents a single address.
	// For example, for the subnet "1.2-3.4.5-6", the address "1.3.4.6" is returned.
	GetUpperIPAddress() *IPAddress
	// CopyNetIP copies the value of the lowest individual address in a subnet or address range into net.IP.
	// If the value can fit into a given net.IP slice, the value is copied into that slice and a length-adjusted subslice is returned.
	// Otherwise, a new slice is created and returned with the value.
	CopyNetIP(bytes net.IP) net.IP
	// CopyUpperNetIP copies the value of the highest individual address in a subnet or address range to net.IP.
	// If the value can fit into a given net.IP slice, the value is copied into that slice and a length-adjusted subslice is returned.
	// Otherwise, a new slice is created and returned with the value.
	CopyUpperNetIP(bytes net.IP) net.IP
	// GetNetIP returns the lowest address in a given subnet or address range in the form net.IP.
	GetNetIP() net.IP
	// GetUpperNetIP returns the highest address in a given subnet or address range in the form net.IP.
	GetUpperNetIP() net.IP
	// GetNetNetIPAddr returns the lowest address in a given subnet or address range as netip.Addr.
	GetNetNetIPAddr() netip.Addr
	// GetUpperNetNetIPAddr returns the highest address in a given subnet or address range as netip.Addr.
	GetUpperNetNetIPAddr() netip.Addr
	// IsSequential returns whether the address item represents a range of addresses that are sequential.
	// Consecutive IP address ranges are sequential by definition.
	// Generally, for a subnet, this means that any segment covering a range of values must be followed by segments that are a complete range covering all values.
	// Individual addresses are sequential and CIDR prefix blocks are sequential.
	// The "1.2.3-4.5" subnet is not sequential because the two addresses it represents, "1.2.3.5" and "1.2.4.5", are not sequential ("1.2.3.6" is in between, but not part of the subnet).
	IsSequential() bool
}
