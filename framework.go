package goip

import (
	"fmt"
	"math/big"

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
