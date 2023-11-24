package goip

import (
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"net/netip"
	"sort"
	"strings"
	"unsafe"
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

// UpperBytes returns the highest address in the range, the one with the highest numeric value, as a byte slice.
func (rng *SequentialRange[T]) UpperBytes() []byte {
	return rng.GetUpper().UpperBytes()
}

// CopyUpperBytes copies the value of the highest address in the range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (rng *SequentialRange[T]) CopyUpperBytes(bytes []byte) []byte {
	return rng.GetUpper().CopyUpperBytes(bytes)
}

// GetValue returns the lowest address in the range,
// the one with the lowest numeric value, as an integer.
func (rng *SequentialRange[T]) GetValue() *big.Int {
	return rng.GetLower().GetValue()
}

// GetUpperValue returns the highest address in the range,
// the one with the highest numeric value, as an integer.
func (rng *SequentialRange[T]) GetUpperValue() *big.Int {
	return rng.GetUpper().GetValue()
}

// Iterator provides an iterator to iterate through the individual addresses of this address range.
//
// Call GetCount for the count.
func (rng *SequentialRange[T]) Iterator() Iterator[T] {
	if rng == nil {
		return nilIterator[T]()
	}

	rng = rng.init()
	lower := rng.lower
	if !rng.isMultiple {
		return &singleIterator[T]{original: lower}
	}

	divCount := lower.GetSegmentCount()

	return lower.rangeIterator(
		rng.upper,
		false,
		nil,
		(*IPAddress).GetSegment,
		func(seg *IPAddressSegment, index int) Iterator[*IPAddressSegment] {
			return seg.Iterator()
		},
		func(addr1, addr2 *IPAddress, index int) bool {
			return addr1.getSegment(index).getSegmentValue() == addr2.getSegment(index).getSegmentValue()
		},
		divCount-1,
		divCount,
		nil)
}

// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks of the given prefix length,
// one for each prefix of that length in the address range.
func (rng *SequentialRange[T]) PrefixBlockIterator(prefLength BitCount) Iterator[T] {
	rng = rng.init()
	lower := rng.lower
	if !rng.isMultiple {
		return &singleIterator[T]{original: lower.ToPrefixBlockLen(prefLength)}
	}

	prefLength = checkSubnet(lower, prefLength)
	bitsPerSegment := lower.GetBitsPerSegment()
	bytesPerSegment := lower.GetBytesPerSegment()
	segCount := lower.GetSegmentCount()
	segPrefs := make([]segPrefData, segCount)
	networkSegIndex := getNetworkSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment)
	for i := networkSegIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLength, i)
		segPrefs[i] = segPrefData{segPrefLength, bitsPerSegment - segPrefLength.bitCount()}
	}

	hostSegIndex := getHostSegmentIndex(prefLength, bytesPerSegment, bitsPerSegment)

	return lower.rangeIterator(
		rng.upper,
		true,
		cacheBitCount(prefLength),
		(*IPAddress).GetSegment,
		func(seg *IPAddressSegment, index int) Iterator[*IPAddressSegment] {
			return seg.Iterator()
		},
		func(addr1, addr2 *IPAddress, index int) bool {
			segPref := segPrefs[index]
			if segPref.prefLen == nil {
				return addr1.GetSegment(index).GetSegmentValue() == addr2.GetSegment(index).GetSegmentValue()
			}
			shift := segPref.shift
			return addr1.GetSegment(index).GetSegmentValue()>>uint(shift) == addr2.GetSegment(index).GetSegmentValue()>>uint(shift)

		},
		networkSegIndex,
		hostSegIndex,
		func(seg *IPAddressSegment, index int) Iterator[*IPAddressSegment] {
			segPref := segPrefs[index]
			segPrefLen := segPref.prefLen
			if segPrefLen == nil {
				return seg.Iterator()
			}
			return seg.PrefixedBlockIterator(segPrefLen.bitCount())
		},
	)
}

// Overlaps returns true if this sequential range overlaps with the given sequential range.
func (rng *SequentialRange[T]) Overlaps(other *SequentialRange[T]) bool {
	rng = rng.init()
	return compareLowIPAddressValues(other.GetLower(), rng.upper) <= 0 &&
		compareLowIPAddressValues(other.GetUpper(), rng.lower) >= 0
}

// Intersect returns the intersection of this range with the given range, a range which includes those addresses found in both.
func (rng *SequentialRange[T]) Intersect(other *SequentialRange[T]) *SequentialRange[T] {
	rng = rng.init()
	other = other.init()
	otherLower, otherUpper := other.GetLower(), other.GetUpper()
	lower, upper := rng.lower, rng.upper

	if compareLowIPAddressValues(lower, otherLower) <= 0 {
		if compareLowIPAddressValues(upper, otherUpper) >= 0 { // l, ol, ou, u
			return other
		}
		comp := compareLowIPAddressValues(upper, otherLower)
		if comp < 0 { // l, u, ol, ou
			return nil
		}
		return newSequRangeUnchecked(otherLower, upper, comp != 0) // l, ol, u,  ou
	} else if compareLowIPAddressValues(otherUpper, upper) >= 0 {
		return rng
	}

	comp := compareLowIPAddressValues(otherUpper, lower)
	if comp < 0 {
		return nil
	}

	return newSequRangeUnchecked(lower, otherUpper, comp != 0)
}

// CoverWithPrefixBlock returns the minimal-size prefix block that covers all the addresses in this range.
// The resulting block will have a larger count than this, unless this range already directly corresponds to a prefix block.
func (rng *SequentialRange[T]) CoverWithPrefixBlock() T {
	return rng.GetLower().CoverWithPrefixBlockTo(rng.GetUpper())
}

// SpanWithPrefixBlocks returns an array of prefix blocks that spans the same set of addresses as this range.
func (rng *SequentialRange[T]) SpanWithPrefixBlocks() []T {
	return rng.GetLower().SpanWithPrefixBlocksTo(rng.GetUpper())
}

// SpanWithSequentialBlocks produces the smallest slice of
// sequential blocks that cover the same set of addresses as this range.
// This slice can be shorter than that produced by SpanWithPrefixBlocks and is never longer.
func (rng *SequentialRange[T]) SpanWithSequentialBlocks() []T {
	res := rng.GetLower().SpanWithSequentialBlocksTo(rng.GetUpper())
	return res
}

// JoinTo joins this range to the other if they are contiguous.
// If this range overlaps with the given range,
// or if the highest value of the lower range is one below the lowest value of the higher range,
// then the two are joined into a new larger range that is returned.
// Otherwise, nil is returned.
func (rng *SequentialRange[T]) JoinTo(other *SequentialRange[T]) *SequentialRange[T] {
	rng = rng.init()
	other = other.init()
	otherLower, otherUpper := other.GetLower(), other.GetUpper()
	lower, upper := rng.lower, rng.upper
	lowerComp := compareLowIPAddressValues(lower, otherLower)
	if !rng.Overlaps(other) {
		if lowerComp >= 0 {
			if otherUpper.Increment(1).Equal(lower) {
				return newSequRangeUnchecked[T](otherLower, upper, true)
			}
		} else {
			if upper.Increment(1).Equal(otherLower) {
				return newSequRangeUnchecked[T](lower, otherUpper, true)
			}
		}
		return nil
	}

	var lowestLower, highestUpper T
	upperComp := compareLowIPAddressValues(upper, otherUpper)

	if lowerComp >= 0 {
		if lowerComp == 0 && upperComp == 0 {
			return rng
		}
		lowestLower = otherLower
	} else {
		lowestLower = lower
	}

	if upperComp >= 0 {
		highestUpper = upper
	} else {
		highestUpper = otherUpper
	}

	return newSequRangeUnchecked(lowestLower, highestUpper, true)
}

// IsIPv4 returns true if this sequential address range is an IPv4 sequential address range.
// If so, use ToIPv4 to convert to the IPv4-specific type.
func (rng *SequentialRange[T]) IsIPv4() bool { // returns false when lower is nil
	if rng != nil {
		t := any(rng.GetLower())
		if _, ok := t.(*IPv4Address); ok {
			return true
		} else if addr, ok := t.(*IPAddress); ok {
			return addr.IsIPv4()
		}
	}
	return false
}

// IsIPv6 returns true if this sequential address range is an IPv6 sequential address range.
// If so, use ToIPv6 to convert to the IPv6-specific type.
func (rng *SequentialRange[T]) IsIPv6() bool { // returns false when lower is nil
	if rng != nil {
		t := any(rng.GetLower())
		if _, ok := t.(*IPv6Address); ok {
			return true
		} else if addr, ok := t.(*IPAddress); ok {
			return addr.IsIPv6()
		}
	}
	return false
}

// Extend extends this sequential range to include all address in the given range.
// If the argument has a different IP version than this, nil is returned.
// Otherwise, this method returns the range that includes this range, the given range, and all addresses in-between.
func (rng *SequentialRange[T]) Extend(other *SequentialRange[T]) *SequentialRange[T] {
	rng = rng.init()
	other = other.init()
	if !rng.lower.GetIPVersion().Equal(other.lower.GetIPVersion()) {
		return nil
	}

	otherLower, otherUpper := other.GetLower(), other.GetUpper()
	lower, upper := rng.lower, rng.upper
	lowerComp := compareLowIPAddressValues(lower, otherLower)
	upperComp := compareLowIPAddressValues(upper, otherUpper)
	if lowerComp > 0 { //
		if upperComp <= 0 { // ol l u ou
			return other
		}
		// ol l ou u or ol ou l u
		return newSequRangeUnchecked(otherLower, upper, true)
	}

	if upperComp >= 0 { // l ol ou u
		return rng
	}

	return newSequRangeUnchecked(lower, otherUpper, true) // l ol u ou or l u ol ou
}

// Subtract subtracts the given range from the receiver range, to produce either zero, one,
// or two address ranges that contain the addresses in the receiver range and not in the given range.
// If the result has length 2, the two ranges are ordered by ascending lowest range value.
func (rng *SequentialRange[T]) Subtract(other *SequentialRange[T]) []*SequentialRange[T] {
	rng = rng.init()
	other = other.init()
	otherLower, otherUpper := other.GetLower(), other.GetUpper()
	lower, upper := rng.lower, rng.upper
	if compareLowIPAddressValues(lower, otherLower) < 0 {
		if compareLowIPAddressValues(upper, otherUpper) > 0 { // l ol ou u
			return []*SequentialRange[T]{
				newSequRangeCheckSize(lower, otherLower.Increment(-1)),
				newSequRangeCheckSize(otherUpper.Increment(1), upper),
			}
		} else {
			comp := compareLowIPAddressValues(upper, otherLower)
			if comp < 0 { // l u ol ou
				return []*SequentialRange[T]{rng}
			} else if comp == 0 { // l u == ol ou
				return []*SequentialRange[T]{newSequRangeCheckSize(lower, upper.Increment(-1))}
			}
			return []*SequentialRange[T]{newSequRangeCheckSize(lower, otherLower.Increment(-1))} // l ol u ou
		}
	} else if compareLowIPAddressValues(otherUpper, upper) >= 0 { // ol l u ou
		return make([]*SequentialRange[T], 0, 0)
	} else {
		comp := compareLowIPAddressValues(otherUpper, lower)
		if comp < 0 {
			return []*SequentialRange[T]{rng} // ol ou l u
		} else if comp == 0 {
			return []*SequentialRange[T]{newSequRangeCheckSize(lower.Increment(1), upper)} // ol ou == l u
		}
		return []*SequentialRange[T]{newSequRangeCheckSize(otherUpper.Increment(1), upper)} // ol l ou u
	}
}

// GetIPVersion returns the IP version of this IP address sequential range
func (rng *SequentialRange[T]) GetIPVersion() IPVersion {
	return rng.init().lower.GetIPVersion()
}

func (rng *SequentialRange[T]) getCachedCount(copy bool) (res *big.Int) {
	cache := rng.cache
	count := (*big.Int)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))))
	if count == nil {
		if !rng.IsMultiple() {
			count = bigOne()
		} else {
			lower := rng.lower
			upper := rng.upper
			if ipv4Lower, ok := any(lower).(*IPv4Address); ok {
				ipv4Upper := any(upper).(*IPv4Address)
				val := int64(ipv4Upper.Uint32Value()) - int64(ipv4Lower.Uint32Value()) + 1
				count = new(big.Int).SetInt64(val)
			} else {
				count = upper.GetValue()
				res = lower.GetValue()
				count.Sub(count, res).Add(count, bigOneConst())
				res.Set(count)
			}
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomicStorePointer(dataLoc, unsafe.Pointer(count))
	}

	if res == nil {
		if copy {
			res = new(big.Int).Set(count)
		} else {
			res = count
		}
	}

	return
}

// GetPrefixCountLen returns the count of the number of distinct values within
// the prefix part of the range of addresses.
func (rng *SequentialRange[T]) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if !rng.IsMultiple() { // also checks for zero-ranges
		return bigOne()
	}

	bitCount := rng.lower.GetBitCount()
	if prefixLen <= 0 {
		return bigOne()
	} else if prefixLen >= bitCount {
		return rng.GetCount()
	}

	shiftAdjustment := bitCount - prefixLen
	lower := rng.lower
	if ipv4Lower, ok := any(lower).(*IPv4Address); ok {
		ipv4Upper := any(rng.upper).(*IPv4Address)
		upperAdjusted := ipv4Upper.Uint32Value() >> uint(shiftAdjustment)
		lowerAdjusted := ipv4Lower.Uint32Value() >> uint(shiftAdjustment)
		result := int64(upperAdjusted) - int64(lowerAdjusted) + 1
		return new(big.Int).SetInt64(result)
	}

	upperVal := rng.upper.GetValue()
	ushiftAdjustment := uint(shiftAdjustment)
	upperVal.Rsh(upperVal, ushiftAdjustment)
	lowerVal := lower.GetValue()
	lowerVal.Rsh(lowerVal, ushiftAdjustment)
	upperVal.Sub(upperVal, lowerVal).Add(upperVal, bigOneConst())
	return upperVal
}

// GetCount returns the count of addresses that this sequential range spans.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (rng *SequentialRange[T]) GetCount() *big.Int {
	if rng == nil {
		return bigZero()
	}
	return rng.init().getCachedCount(true)
}

// Compare returns a negative integer, zero, or a positive integer if
// this sequential address range is less than, equal, or greater than the given item.
// Any address item is comparable to any other.
// All address items use CountComparator to compare.
func (rng *SequentialRange[T]) Compare(item AddressItem) int {
	if rng != nil {
		rng = rng.init()
	}
	return CountComparator.Compare(rng, item)
}

// CompareSize compares the counts of two address ranges or items,
// the number of individual addresses or items within each.
//
// Rather than calculating counts with GetCount,
// there can be more efficient ways of determining whether this range spans more individual addresses than another item.
//
// CompareSize returns a positive integer if this range has a larger count than the item given,
// zero if they are the same, or a negative integer if the other has a larger count.
func (rng *SequentialRange[T]) CompareSize(other AddressItem) int {
	if rng == nil {
		if isNilItem(other) {
			return 0
		}
		// we have size 0, other has size >= 1
		return -1
	}
	return compareCount(rng, other)
}

// ToKey creates the associated address range key.
// While address ranges can be compared with the Compare or Equal methods
// as well as various provided instances of AddressComparator,
// they are not comparable with Go operators.
// However, SequentialRangeKey instances are comparable with Go operators,
// and thus can be used as map keys.
func (rng *SequentialRange[T]) ToKey() SequentialRangeKey[T] {
	return newSequentialRangeKey(rng.init())
}

// PrefixIterator provides an iterator to iterate through the individual prefixes of the given prefix length in this address range,
// each iterated element spanning the range of values for its prefix.
//
// It is similar to the prefix block iterator, except for possibly the first and last iterated elements, which might not be prefix blocks,
// instead constraining themselves to values from this range.
//
// Since a range between two arbitrary addresses cannot always be represented with a single IPAddress instance,
// the returned iterator iterates through SequentialRange instances.
//
// For instance, if iterating from "1.2.3.4" to "1.2.4.5" with prefix 8, the range shares the same prefix of value 1,
// but the range cannot be represented by the address "1.2.3-4.4-5" which does not include "1.2.3.255" or "1.2.4.0" both of which are in the original range.
// Nor can the range be represented by "1.2.3-4.0-255" which includes "1.2.4.6" and "1.2.3.3", both of which were not in the original range.
// A SequentialRange is thus required to represent that prefixed range.
func (rng *SequentialRange[T]) PrefixIterator(prefLength BitCount) Iterator[*SequentialRange[T]] {
	rng = rng.init()
	lower := rng.lower
	if !rng.isMultiple {
		return &singleIterator[*SequentialRange[T]]{original: rng}
	}
	prefLength = checkSubnet(lower, prefLength)
	return &sequRangeIterator[T]{
		rng:                 rng,
		creator:             newSequRange[T],
		prefixBlockIterator: rng.PrefixBlockIterator(prefLength),
		prefixLength:        prefLength,
	}
}

// Contains returns whether this range contains all addresses in the given address or subnet.
func (rng *SequentialRange[T]) Contains(other IPAddressType) bool {
	if rng == nil {
		return other == nil || other.ToAddressBase() == nil
	} else if other == nil {
		return true
	}
	otherAddr := other.ToIP()
	if otherAddr == nil {
		return true
	}
	rng = rng.init()
	return compareLowIPAddressValues(otherAddr.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherAddr.GetUpper(), rng.upper) <= 0
}

// ContainsRange returns whether all the addresses in the given sequential range are also contained in this sequential range.
func (rng *SequentialRange[T]) ContainsRange(other IPAddressSeqRangeType) bool {
	if rng == nil {
		return other == nil || other.ToIP() == nil
	} else if other == nil {
		return true
	}

	rng = rng.init()
	otherRange := other.ToIP()
	if otherRange == nil {
		return true
	}

	return compareLowIPAddressValues(otherRange.GetLower(), rng.lower) >= 0 &&
		compareLowIPAddressValues(otherRange.GetUpper(), rng.upper) <= 0
}

// Equal returns whether the given sequential address range is equal to this sequential address range.
// Two sequential address ranges are equal if their lower and upper range boundaries are equal.
func (rng *SequentialRange[T]) Equal(other IPAddressSeqRangeType) bool {
	if rng == nil {
		return other == nil || other.ToIP() == nil
	} else if other == nil {
		return false
	}

	rng = rng.init()
	otherRange := other.ToIP()
	if otherRange == nil {
		return false
	}

	return rng.lower.Equal(otherRange.GetLower()) && rng.upper.Equal(otherRange.GetUpper())
}

// ToIP converts to a SequentialRange[*IPAddress],
// a polymorphic type usable with all IP address sequential ranges.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (rng *SequentialRange[T]) ToIP() *SequentialRange[*IPAddress] {
	if rng != nil {
		if ip, ok := any(rng).(*SequentialRange[*IPAddress]); ok {
			return ip
		}
		return newSequRangeUnchecked(rng.GetLower().ToIP(), rng.GetUpper().ToIP(), rng.isMultiple)
	}
	return nil
}

// ToIPv4 converts to a SequentialRange[*IPv4Address] if this address range is an IPv4 address range.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (rng *SequentialRange[T]) ToIPv4() *SequentialRange[*IPv4Address] {
	if rng != nil {
		if ipv4, ok := any(rng).(*SequentialRange[*IPv4Address]); ok {
			return ipv4
		} else {
			t := any(rng.GetLower())
			if addr, ok := t.(*IPAddress); ok && addr.IsIPv4() {
				t = any(rng.GetUpper())
				return newSequRangeUnchecked(addr.ToIPv4(), t.(*IPAddress).ToIPv4(), rng.isMultiple)
			}
		}
	}
	return nil
}

// ToIPv6 converts to a SequentialRange[*IPv6Address] if this address range is an IPv6 address range.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (rng *SequentialRange[T]) ToIPv6() *SequentialRange[*IPv6Address] {
	if rng != nil {
		if ipv6, ok := any(rng).(*SequentialRange[*IPv6Address]); ok {
			return ipv6
		} else {
			t := any(rng.GetLower())
			if addr, ok := t.(*IPAddress); ok && addr.IsIPv6() {
				t = any(rng.GetUpper())
				return newSequRangeUnchecked(addr.ToIPv6(), t.(*IPAddress).ToIPv6(), rng.isMultiple)
			}
		}
	}
	return nil
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

func joinRanges[T SequentialRangeConstraint[T]](ranges []*SequentialRange[T]) []*SequentialRange[T] {
	// nil entries are automatic joins
	joinedCount := 0
	rangesLen := len(ranges)
	for i, j := 0, rangesLen-1; i <= j; i++ {
		if ranges[i] == nil {
			joinedCount++
			for ranges[j] == nil && j > i {
				j--
				joinedCount++
			}
			if j > i {
				ranges[i] = ranges[j]
				ranges[j] = nil
				j--
			}
		}
	}

	rangesLen = rangesLen - joinedCount
	ranges = ranges[:rangesLen]
	joinedCount = 0
	sort.Slice(ranges, func(i, j int) bool {
		return LowValueComparator.CompareRanges(ranges[i], ranges[j]) < 0
	})
	for i := 0; i < rangesLen; {
		rng := ranges[i]
		currentLower, currentUpper := rng.GetLower(), rng.GetUpper()
		var isMultiJoin, didJoin bool
		j := i + 1
		for ; j < rangesLen; j++ {
			rng2 := ranges[j]
			nextLower := rng2.GetLower()
			doJoin := compareLowIPAddressValues(currentUpper, nextLower) >= 0
			if !doJoin && nextLower.GetIPVersion().Equal(currentUpper.GetIPVersion()) {
				doJoin = currentUpper.Increment(1).Equal(nextLower)
				isMultiJoin = true
			}
			if doJoin {
				//Join them
				joinedCount++
				nextUpper := rng2.GetUpper()
				if compareLowIPAddressValues(currentUpper, nextUpper) < 0 {
					currentUpper = nextUpper
				}
				ranges[j] = nil
				isMultiJoin = isMultiJoin || rng.isMultiple || rng2.isMultiple
				didJoin = true
			} else {
				break
			}
		}
		if didJoin {
			ranges[i] = newSequRangeUnchecked(currentLower, currentUpper, isMultiJoin)
		}
		i = j
	}

	finalLen := rangesLen - joinedCount
	if finalLen > 0 {
		for i, j := 0, 0; ; i++ {
			rng := ranges[i]
			if rng == nil {
				continue
			}
			ranges[j] = rng
			j++
			if j >= finalLen {
				break
			}
		}
	}

	ret := ranges[:finalLen]
	return ret
}
