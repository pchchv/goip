package goip

import (
	"fmt"
	"math/big"
	"math/bits"
)

// DefaultSeqRangeSeparator is the low to high value separator used when creating strings for IP ranges.
const DefaultSeqRangeSeparator = " -> "

type rangeCache struct {
	cachedCount *big.Int
}

// SequentialRangeConstraint is the generic type constraint for an IP address sequential range.
type SequentialRangeConstraint[T any] interface {
	// cannot use IPAddressType here because ToAddressString() results in a circular dependency,
	// SequentialRangeConstraint -> IPAddressType -> IPAddressString -> SequentialRange -> SequentialRangeConstraint
	AddressType
	IPAddressRange
	comparable
	ToIP() *IPAddress
	PrefixedConstraint[T]
	Increment(int64) T
	GetLower() T
	GetUpper() T
	CoverWithPrefixBlockTo(T) T
	SpanWithPrefixBlocksTo(T) []T
	SpanWithSequentialBlocksTo(T) []T
	SpanWithPrefixBlocks() []T
	IncludesZeroHostLen(BitCount) bool
	IncludesMaxHostLen(BitCount) bool
	Format(state fmt.State, verb rune)
	rangeIterator(upper T,
		valsAreMultiple bool,
		prefixLen PrefixLen,
		segProducer func(addr *IPAddress, index int) *IPAddressSegment,
		segmentIteratorProducer func(seg *IPAddressSegment, index int) Iterator[*IPAddressSegment],
		segValueComparator func(seg1, seg2 *IPAddress, index int) bool,
		networkSegmentIndex,
		hostSegmentIndex int,
		prefixedSegIteratorProducer func(seg *IPAddressSegment, index int) Iterator[*IPAddressSegment],
	) Iterator[T]
	equalsSameVersion(AddressType) bool
	getLowestHighestAddrs() (lower, upper T)
	getAddrType() addrType
}

// SequentialRange represents an arbitrary range of consecutive IP addresses, starting from the lowest address and ending at the top address, inclusive.
//
// For a generic T type, you can select *IPAddress, *IPv4Address, or *IPv6Address.
//
// This type allows any sequential range of addresses to be represented, including those that cannot be represented in [IPAddress] or [IPAddressString].
//
// [IPAddress] and [IPAddressString] allow a range of values to be specified for each segment,
// allowing single addresses, any address subnet with a CIDR prefix
// (e.g., "1.2.0.0/16" or "1:2:3:4::/64"), or any subnet that can be represented using segment ranges (e.g., "1.2.0-255.*" or "1:2:3:4:*").
// See [IPAddressString] for more details.
// [IPAddressString] and [IPAddress] cover all potential subnets and addresses that can be represented by
// a single address string of 4 or less segments for IPv4 and 8 or less segments for IPv6.
// In contrast, this type covers any sequential address range.
//
// String representations of this type include the full address for both the lower and upper bounds of the range.
//
// A zero value represents the range from the zero-valued of [IPAddress] to itself.
//
// For a range of type SequentialRange[*IPAddress], the range extends from an IPv4 address to another IPv4 address or from an IPv6 address to another IPv6 address.
// A sequential range cannot include both IPv4 and IPv6 addresses.
type SequentialRange[T SequentialRangeConstraint[T]] struct {
	lower      T
	upper      T
	isMultiple bool // set on construction, even for zero values
	cache      *rangeCache
}

// getMinPrefixLenForBlock returns the smallest prefix length such that the
// upper and lower values span the block of values for that prefix length.
// The given bit count indicates the bits that matter in the two values, the remaining bits are ignored.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use getPrefixLenForSingleBlock to avoid the case of multiple prefix values.
func getMinPrefixLenForBlock(lower, upper DivInt, bitCount BitCount) BitCount {
	if lower == upper {
		return bitCount
	} else if lower == 0 {
		maxValue := ^(^DivInt(0) << uint(bitCount))
		if upper == maxValue {
			return 0
		}
	}

	result := bitCount
	lowerZeros := bits.TrailingZeros64(lower)
	if lowerZeros != 0 {
		upperOnes := bits.TrailingZeros64(^upper)
		if upperOnes != 0 {
			var prefixedBitCount int
			if lowerZeros < upperOnes {
				prefixedBitCount = lowerZeros
			} else {
				prefixedBitCount = upperOnes
			}
			result -= BitCount(prefixedBitCount)
		}
	}

	return result
}
