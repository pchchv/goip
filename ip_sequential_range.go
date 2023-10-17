package goip

import (
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"net/netip"
	"strings"
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

// ContainsSinglePrefixBlock returns whether this address range contains a single prefix block for the given prefix length.
//
// This means there is only one prefix value for the given prefix length,
// and it also contains the full prefix block for that prefix, all addresses with that prefix.
//
// Use GetPrefixLenForSingleBlock to determine whether there is a prefix length for which this method returns true.
func (rng *SequentialRange[T]) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	lower := rng.lower
	upper := rng.upper
	if lower == upper { // also handles zero-value case nil lower and upper
		return true
	}

	var prevBitCount BitCount
	prefixLen = checkSubnet(lower, prefixLen)
	divCount := lower.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		div := lower.GetGenericSegment(i)
		upperDiv := upper.GetGenericSegment(i)
		bitCount := div.GetBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen >= totalBitCount {
			if !segValSame(div.GetSegmentValue(), upperDiv.GetSegmentValue()) {
				return false
			}
		} else {
			divPrefixLen := prefixLen - prevBitCount
			if !isPrefixBlockVals(DivInt(div.GetSegmentValue()), DivInt(upperDiv.GetSegmentValue()), divPrefixLen, div.GetBitCount()) {
				return false
			}
			for i++; i < divCount; i++ {
				div = lower.GetGenericSegment(i)
				upperDiv = upper.GetGenericSegment(i)
				if !div.IncludesZero() || !upperDiv.IncludesMax() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

// GetPrefixLenForSingleBlock returns a prefix length for which there is only one prefix in this range,
// and the range of values in this range matches the block of all values for that prefix.
//
// If the range can be described this way, then this method returns the same value as GetMinPrefixLenForBlock.
//
// If no such prefix length exists, returns nil.
//
// If this item represents a single value, this returns the bit count.
func (rng *SequentialRange[T]) GetPrefixLenForSingleBlock() PrefixLen {
	rng = rng.init()
	lower := rng.lower
	upper := rng.upper
	count := lower.GetSegmentCount()
	segBitCount := lower.GetBitsPerSegment()
	maxSegValue := ^(^SegInt(0) << uint(segBitCount))
	totalPrefix := BitCount(0)
	for i := 0; i < count; i++ {
		lowerSeg := lower.GetGenericSegment(i)
		upperSeg := upper.GetGenericSegment(i)
		segPrefix := getPrefixLenForSingleBlock(DivInt(lowerSeg.GetSegmentValue()), DivInt(upperSeg.GetSegmentValue()), segBitCount)
		if segPrefix == nil {
			return nil
		}
		dabits := segPrefix.bitCount()
		totalPrefix += dabits
		if dabits < segBitCount {
			//remaining segments must be full range or we return nil
			for i++; i < count; i++ {
				lowerSeg = lower.GetGenericSegment(i)
				upperSeg = upper.GetGenericSegment(i)
				if lowerSeg.GetSegmentValue() != 0 {
					return nil
				} else if upperSeg.GetSegmentValue() != maxSegValue {
					return nil
				}
			}
		}
	}
	return cacheBitCount(totalPrefix)
}

// IsMultiple returns whether this range represents a range of multiple addresses.
func (rng *SequentialRange[T]) IsMultiple() bool {
	return rng != nil && rng.isMultiple
}

// IsMax returns whether this sequential range spans from the max address,
// the address whose bits are all ones, to itself.
func (rng *SequentialRange[T]) IsMax() bool {
	return rng.IncludesMax() && !rng.IsMultiple()
}

// IncludesMax returns whether this sequential range's upper value is the max value,
// the value whose bits are all ones.
func (rng *SequentialRange[T]) IncludesMax() bool {
	return rng.init().upper.IsMax()
}

// IsZero returns whether this sequential range spans from the zero address to itself.
func (rng *SequentialRange[T]) IsZero() bool {
	return rng.IncludesZero() && !rng.IsMultiple()
}

// IncludesZero returns whether this sequential range's lower value is the zero address.
func (rng *SequentialRange[T]) IncludesZero() bool {
	return rng.init().lower.IsZero()
}

// IsFullRange returns whether this address range covers the entire address space of this IP address version.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (rng *SequentialRange[T]) IsFullRange() bool {
	return rng.IncludesZero() && rng.IncludesMax()
}

// ToString produces a customized string for the address range.
func (rng *SequentialRange[T]) ToString(lowerStringer func(T) string, separator string, upperStringer func(T) string) string {
	if rng == nil {
		return nilString()
	}
	rng = rng.init()
	builder := strings.Builder{}
	str1, str2, str3 := lowerStringer(rng.lower), separator, upperStringer(rng.upper)
	builder.Grow(len(str1) + len(str2) + len(str3))
	builder.WriteString(str1)
	builder.WriteString(str2)
	builder.WriteString(str3)
	return builder.String()
}

// String implements the [fmt.Stringer] interface,
// returning the lower address canonical string, followed by the default separator " -> ",
// followed by the upper address canonical string.
// It returns "<nil>" if the receiver is a nil pointer.
func (rng *SequentialRange[T]) String() string {
	if rng == nil {
		return nilString()
	}
	return rng.ToString(T.String, DefaultSeqRangeSeparator, T.String)
}

// ToNormalizedString produces a normalized string for the address range.
// It has the format "lower -> upper" where lower and upper are
// the normalized strings for the lowest and highest addresses in the range,
// given by GetLower and GetUpper.
func (rng *SequentialRange[T]) ToNormalizedString() string {
	return rng.ToString(T.ToNormalizedString, DefaultSeqRangeSeparator, T.ToNormalizedString)
}

// ToCanonicalString produces a canonical string for the address range.
// It has the format "lower -> upper" where lower and upper are
// the canonical strings for the lowest and highest addresses in the range,
// given by GetLower and GetUpper.
func (rng *SequentialRange[T]) ToCanonicalString() string {
	return rng.ToString(T.ToCanonicalString, DefaultSeqRangeSeparator, T.ToCanonicalString)
}

// Format implements [fmt.Formatter] interface.
//
// It prints the string as "lower -> upper" where lower and upper are the formatted strings for
// the lowest and highest addresses in the range, given by GetLower and GetUpper.
// The formats, flags, and other specifications supported are those supported by Format in IPAddress.
func (rng SequentialRange[T]) Format(state fmt.State, verb rune) {
	rngPtr := rng.init()
	rngPtr.lower.Format(state, verb)
	_, _ = state.Write([]byte(DefaultSeqRangeSeparator))
	rngPtr.upper.Format(state, verb)
}

// GetLower returns the lowest address in the range,
// the one with the lowest numeric value.
func (rng *SequentialRange[T]) GetLower() T {
	return rng.init().lower
}

// GetUpper returns the highest address in the range,
// the one with the highest numeric value.
func (rng *SequentialRange[T]) GetUpper() T {
	return rng.init().upper
}

// GetLowerIPAddress satisfies the IPAddressRange interface,
// returning the lower address in the range, same as GetLower.
func (rng *SequentialRange[T]) GetLowerIPAddress() *IPAddress {
	return rng.GetLower().ToIP()
}

// GetUpperIPAddress satisfies the IPAddressRange interface,
// returning the upper address in the range, same as GetUpper.
func (rng *SequentialRange[T]) GetUpperIPAddress() *IPAddress {
	return rng.GetUpper().ToIP()
}

// GetBitCount returns the number of bits in each address in the range.
func (rng *SequentialRange[T]) GetBitCount() BitCount {
	return rng.GetLower().GetBitCount()
}

// GetByteCount returns the number of bytes in each address in the range.
func (rng *SequentialRange[T]) GetByteCount() int {
	return rng.GetLower().GetByteCount()
}

// GetNetIP returns the lower IP address in the range as a net.IP.
func (rng *SequentialRange[T]) GetNetIP() net.IP {
	return rng.GetLower().GetNetIP()
}

// GetUpperNetIP returns the upper IP address in the range as a net.IP.
func (rng *SequentialRange[T]) GetUpperNetIP() net.IP {
	return rng.GetUpper().GetUpperNetIP()
}

// GetNetNetIPAddr returns the lowest address in this address range as a netip.Addr.
func (rng *SequentialRange[T]) GetNetNetIPAddr() netip.Addr {
	return rng.GetLower().GetNetNetIPAddr()
}

// GetUpperNetNetIPAddr returns the highest address in this address range as a netip.Addr.
func (rng *SequentialRange[T]) GetUpperNetNetIPAddr() netip.Addr {
	return rng.GetUpper().GetUpperNetNetIPAddr()
}

// CopyNetIP copies the value of the lower IP address in the range into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (rng *SequentialRange[T]) CopyNetIP(bytes net.IP) net.IP {
	return rng.GetLower().CopyNetIP(bytes) // changes the arg to 4 bytes if 16 bytes and ipv4
}

// CopyUpperNetIP copies the upper IP address in the range into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (rng *SequentialRange[T]) CopyUpperNetIP(bytes net.IP) net.IP {
	return rng.GetUpper().CopyUpperNetIP(bytes) // changes the arg to 4 bytes if 16 bytes and ipv4
}

// Bytes returns the lowest address in the range, the one with the lowest numeric value, as a byte slice.
func (rng *SequentialRange[T]) Bytes() []byte {
	return rng.GetLower().Bytes()
}

// CopyBytes copies the value of the lowest address in the range into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (rng *SequentialRange[T]) CopyBytes(bytes []byte) []byte {
	return rng.GetLower().CopyBytes(bytes)
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
