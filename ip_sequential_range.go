package goip

import (
	"fmt"
	"math/big"
	"math/bits"
)

// DefaultSeqRangeSeparator is the low to high value separator used when creating strings for IP ranges.
const DefaultSeqRangeSeparator = " -> "

var (
	_ SequentialRange[*IPAddress]
	_ SequentialRange[*IPv4Address]
	_ SequentialRange[*IPv6Address]
)

type IPAddressSeqRange = SequentialRange[*IPAddress]

type IPv4AddressSeqRange = SequentialRange[*IPv4Address]

type IPv6AddressSeqRange = SequentialRange[*IPv6Address]

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

func nilConvert[T SequentialRangeConstraint[T]]() (t T) {
	anyt := any(t)

	if _, ok := anyt.(*IPv6Address); ok {
		t = any(zeroIPv6).(T)
	} else if _, ok := anyt.(*IPv4Address); ok {
		t = any(zeroIPv4).(T)
	} else if _, ok := anyt.(*IPAddress); ok {
		t = any(zeroIPAddr).(T)
	}

	return
}

func newSequRangeUnchecked[T SequentialRangeConstraint[T]](lower, upper T, isMult bool) *SequentialRange[T] {
	return &SequentialRange[T]{
		lower:      lower,
		upper:      upper,
		isMultiple: isMult,
		cache:      &rangeCache{},
	}
}

func newSequRangeCheckSize[T SequentialRangeConstraint[T]](lower, upper T) *SequentialRange[T] {
	return newSequRangeUnchecked(lower, upper, !lower.equalsSameVersion(upper))
}

func compareLowIPAddressValues(one, two AddressType) int {
	return LowValueComparator.CompareAddresses(one, two)
}

func newSequRange[T SequentialRangeConstraint[T]](first, other T) *SequentialRange[T] {
	var lower, upper T
	var isMult bool
	if f := first.Contains(other); f || other.Contains(first) {
		var addr T
		if f {
			addr = first.WithoutPrefixLen()
		} else {
			addr = other.WithoutPrefixLen()
		}
		lower = addr.GetLower()
		if isMult = addr.IsMultiple(); isMult {
			upper = addr.GetUpper()
		} else {
			upper = lower
		}
	} else {
		// We find the lowest and the highest from both supplied addresses
		firstLower := first.GetLower()
		otherLower := other.GetLower()
		firstUpper := first.GetUpper()
		otherUpper := other.GetUpper()
		if comp := compareLowIPAddressValues(firstLower, otherLower); comp > 0 {
			isMult = true
			lower = otherLower
		} else {
			isMult = comp < 0
			lower = firstLower
		}
		if comp := compareLowIPAddressValues(firstUpper, otherUpper); comp < 0 {
			isMult = true
			upper = otherUpper
		} else {
			isMult = isMult || comp > 0
			upper = firstUpper
		}
		if isMult = isMult || compareLowIPAddressValues(lower, upper) != 0; isMult {
			lower = lower.WithoutPrefixLen()
			upper = upper.WithoutPrefixLen()
		} else {
			if lower.IsPrefixed() {
				if upper.IsPrefixed() {
					lower = lower.WithoutPrefixLen()
					upper = lower
				} else {
					lower = upper
				}
			} else {
				upper = lower
			}
		}
	}
	return newSequRangeUnchecked(lower, upper, isMult)
}
