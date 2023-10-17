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

type segPrefData struct {
	prefLen PrefixLen
	shift   BitCount
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

func (rng *SequentialRange[T]) init() *SequentialRange[T] {
	var t T
	if rng.lower == t { // nil for pointers
		t = nilConvert[T]()
		zeroSeqRange := newSequRange(t, t)
		return zeroSeqRange
	}
	return rng
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this includes the block of addresses for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
func (rng *SequentialRange[T]) GetMinPrefixLenForBlock() BitCount {
	rng = rng.init()
	lower := rng.lower
	upper := rng.upper
	count := lower.GetSegmentCount()
	totalPrefix := lower.GetBitCount()
	segBitCount := lower.GetBitsPerSegment()

	for i := count - 1; i >= 0; i-- {
		lowerSeg := lower.GetGenericSegment(i)
		upperSeg := upper.GetGenericSegment(i)
		segPrefix := getMinPrefixLenForBlock(DivInt(lowerSeg.GetSegmentValue()), DivInt(upperSeg.GetSegmentValue()), segBitCount)
		if segPrefix == segBitCount {
			break
		} else {
			totalPrefix -= segBitCount
			if segPrefix != 0 {
				totalPrefix += segPrefix
				break
			}
		}
	}
	return totalPrefix
}

// IsSequential returns whether the address or subnet represents a range of values that are sequential.
//
// IP address sequential ranges are sequential by definition, so this returns true.
func (rng *SequentialRange[T]) IsSequential() bool {
	return true
}

// ContainsPrefixBlock returns whether the range contains the block of addresses for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine whether there is a prefix length for which this method returns true.
func (rng *SequentialRange[T]) ContainsPrefixBlock(prefixLen BitCount) bool {
	lower := rng.lower
	upper := rng.upper
	if lower == upper { // also handles zero-value case nil lower and upper
		return true
	}

	divCount := lower.GetDivisionCount()
	prefixLen = checkSubnet(lower, prefixLen)
	bitsPerSegment := lower.GetBitsPerSegment()
	i := getHostSegmentIndex(prefixLen, lower.GetBytesPerSegment(), bitsPerSegment)
	if i < divCount {
		div := lower.GetGenericSegment(i)
		upperDiv := upper.GetGenericSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLen, i)
		if !isPrefixBlockVals(DivInt(div.GetSegmentValue()), DivInt(upperDiv.GetSegmentValue()), segmentPrefixLength.bitCount(), div.GetBitCount()) {
			return false
		}
		for i++; i < divCount; i++ {
			div = lower.GetGenericSegment(i)
			upperDiv = upper.GetGenericSegment(i)
			//is full range?
			if !div.IncludesZero() || !upperDiv.IncludesMax() {
				return false
			}
		}
	}
	return true
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

// NewSequentialRange creates a sequential range from the given addresses.
// If the type of T is *IPAddress and the versions of lower and upper do not match (one is IPv4, one IPv6), then nil is returned.
// Otherwise, the range is returned.
func NewSequentialRange[T SequentialRangeConstraint[T]](lower, upper T) *SequentialRange[T] {
	var t T
	if lower == t && upper == t { // nil for pointers
		lower = nilConvert[T]()
	} else if lower != t && upper != t {
		// this check only matters when T is *IPAddress
		if lower.getAddrType() != upper.getAddrType() {
			// when both are zero-type, we do not go in here
			// but if only one is, we return nil.  zero-type is "indeterminate", so we cannot "infer" a different version for it
			// However, nil is the absence of a version/type so we can and do
			return nil
		}
	}
	return newSequRange(lower, upper)
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

// getPrefixLenForSingleBlock returns a prefix length for which the given lower and upper values share the same prefix,
// and the range spanned by those values matches exactly the block of all values for that prefix.
// The given bit count indicates the bits that matter in the two values, the remaining bits are ignored.
//
// If the range can be described this way, then this method returns the same value as GetMinPrefixLenForBlock.
//
// If no such prefix length exists, returns nil.
//
// If lower and upper values are the same, this returns the bit count.
func getPrefixLenForSingleBlock(lower, upper DivInt, bitCount BitCount) PrefixLen {
	prefixLen := getMinPrefixLenForBlock(lower, upper, bitCount)
	if prefixLen == bitCount {
		if lower == upper {
			return cacheBitCount(prefixLen)
		}
	} else {
		shift := bitCount - prefixLen
		if lower>>uint(shift) == upper>>uint(shift) {
			return cacheBitCount(prefixLen)
		}
	}
	return nil
}
