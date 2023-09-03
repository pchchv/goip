package goip

import (
	"math/big"
	"unsafe"
)

type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

// GetSegmentPrefixLen returns the network prefix for the segment.
// For an address like "1.2.0.0.0/16", the network prefix is 16.
// When it comes to each address division or segment,
// the prefix for the division is the prefix obtained by applying the address or section prefix.
//
// For example, the address is "1.2.0.0.0/20."
// The first segment has no prefix because the address prefix 20 extends beyond
// the 8 bits of the first segment and is not even applied to it.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which lie in the second segment, it does not apply to that segment either.
// The third segment has a prefix of 4 because
// the address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network section of the address or segment.
// The last segment is prefixed with 0 because not
// a single bit of the network section of the address or segment.
//
// Division prefixes applied throughout the address: nil ... nil (1 to the segment bit length) 0 ... 0.
//
// If the segment has no prefix, nil is returned.
func (seg *ipAddressSegmentInternal) GetSegmentPrefixLen() PrefixLen {
	return seg.getDivisionPrefixLength()
}

func (seg *ipAddressSegmentInternal) isPrefixed() bool {
	return seg.GetSegmentPrefixLen() != nil
}

// IsPrefixBlock returns whether the segment has a prefix length and
// the segment range includes the block of values for that prefix length.
// If the prefix length matches the bit count, this returns true.
func (seg *ipAddressSegmentInternal) IsPrefixBlock() bool {
	return seg.isPrefixBlock()
}

// GetPrefixValueCount returns the count of prefixes in this segment for its prefix length,
// or the total count if it has no prefix length.
func (seg *ipAddressSegmentInternal) GetPrefixValueCount() SegIntCount {
	prefixLength := seg.GetSegmentPrefixLen()
	if prefixLength == nil {
		return seg.GetValueCount()
	}
	return getPrefixValueCount(seg.toAddressSegment(), prefixLength.bitCount())
}

// MatchesWithPrefixMask applies the network mask of the given bit-length to
// this segment and then compares the result with the given value masked by the same mask,
// returning true if the resulting range matches the given single value.
func (seg *ipAddressSegmentInternal) MatchesWithPrefixMask(value SegInt, networkBits BitCount) bool {
	mask := seg.GetSegmentNetworkMask(networkBits)
	matchingValue := value & mask
	return matchingValue == (seg.GetSegmentValue()&mask) && matchingValue == (seg.GetUpperSegmentValue()&mask)
}

// IsSinglePrefixBlock returns whether the range matches the value block for a single prefix identified by the prefix length of this address.
// This is similar to IsPrefixBlock, except that it returns false if the subnet has multiple prefixes.
//
// This method differs from ContainsSinglePrefixBlock in that it returns false if no prefix length is assigned to
// the series or the prefix length is different from the prefix length for which ContainsSinglePrefixBlock returns true.
//
// Method is similar to IsPrefixBlock, but returns false if there are multiple prefixes.
func (seg *ipAddressSegmentInternal) IsSinglePrefixBlock() bool {
	cache := seg.getCache()
	if cache != nil {
		res := cache.isSinglePrefBlock
		if res != nil {
			return *res
		}
	}
	if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
		return seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), prefLen.bitCount())
	}
	return false
}

func (seg *ipAddressSegmentInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	val := seg.GetSegmentValue()
	if val == 0 {
		networkMaskLen, hostMaskLen = cacheBitCount(0), cacheBitCount(seg.GetBitCount())
	} else {
		maxVal := seg.GetMaxValue()
		if val == maxVal {
			networkMaskLen, hostMaskLen = cacheBitCount(seg.GetBitCount()), cacheBitCount(0)
		} else {
			var shifted SegInt
			trailingOnes := seg.GetTrailingBitCount(true)
			if trailingOnes == 0 {
				// can only be 11110000 and not 00000000
				trailingZeros := seg.GetTrailingBitCount(false)
				shifted = (^val & maxVal) >> uint(trailingZeros)
				if shifted == 0 {
					networkMaskLen = cacheBitCount(seg.GetBitCount() - trailingZeros)
				}
			} else {
				// can only be 00001111 and not 11111111
				shifted = val >> uint(trailingOnes)
				if shifted == 0 {
					hostMaskLen = cacheBitCount(seg.GetBitCount() - trailingOnes)
				}
			}
		}
	}
	return
}

// GetBlockMaskPrefixLen returns the prefix length if this address segment is equivalent to a CIDR prefix block mask.
// Otherwise, nil is returned.
//
// A CIDR network mask is a segment with all ones in the network bits followed by all zeros in the host bits.
// A CIDR host mask is a segment with all zeros in the network bits followed by all ones in the host bits.
// The length of the prefix is equal to the length of the network bits.
//
// Note also that the prefix length returned by this method is not equivalent to the prefix length of this segment.
// The prefix length returned here indicates whether the value of this segment can be used as a mask for the network and host bits of any other segment.
// Therefore, the two values may be different, or one may be nil and the other may not.
//
// This method applies only to the lowest value of the range if this segment represents multiple values.
func (seg *ipAddressSegmentInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	hostLength := seg.GetTrailingBitCount(!network)
	var shifted SegInt
	val := seg.GetSegmentValue()
	if network {
		maxVal := seg.GetMaxValue()
		shifted = (^val & maxVal) >> uint(hostLength)
	} else {
		shifted = val >> uint(hostLength)
	}
	if shifted == 0 {
		return cacheBitCount(seg.GetBitCount() - hostLength)
	}
	return nil
}

func (seg *ipAddressSegmentInternal) setStandardString(
	addressStr string,
	isStandardString bool,
	lowerStringStartIndex,
	lowerStringEndIndex int,
	originalLowerValue SegInt) {
	if cache := seg.getCache(); cache != nil {
		if isStandardString && originalLowerValue == seg.getSegmentValue() {
			cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:lowerStringEndIndex] })
		}
	}
}

func (seg *ipAddressSegmentInternal) setWildcardString(
	addressStr string,
	isStandardString bool,
	lowerStringStartIndex,
	lowerStringEndIndex int,
	lowerValue SegInt) {
	if cache := seg.getCache(); cache != nil {
		if isStandardString &&
			lowerValue == seg.getSegmentValue() &&
			lowerValue == seg.getUpperSegmentValue() {
			cacheStr(&cache.cachedWildcardString, func() string { return addressStr[lowerStringStartIndex:lowerStringEndIndex] })
		}
	}
}

func (seg *ipAddressSegmentInternal) setRangeStandardString(
	addressStr string,
	isStandardString,
	isStandardRangeString bool,
	lowerStringStartIndex,
	lowerStringEndIndex,
	upperStringEndIndex int,
	rangeLower,
	rangeUpper SegInt) {
	if cache := seg.getCache(); cache != nil {
		if seg.IsSinglePrefixBlock() {
			if isStandardString && rangeLower == seg.getSegmentValue() {
				cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:lowerStringEndIndex] })
			}
		} else if seg.IsFullRange() {
			cacheStrPtr(&cache.cachedString, &segmentWildcardStr)
		} else if isStandardRangeString && rangeLower == seg.getSegmentValue() {
			upper := seg.getUpperSegmentValue()
			if seg.isPrefixed() {
				upper &= seg.GetSegmentNetworkMask(seg.getDivisionPrefixLength().bitCount())
			}
			if rangeUpper == upper {
				cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:upperStringEndIndex] })
			}
		}
	}
}

func (seg *ipAddressSegmentInternal) setRangeWildcardString(
	addressStr string,
	isStandardRangeString bool,
	lowerStringStartIndex,
	upperStringEndIndex int,
	rangeLower,
	rangeUpper SegInt) {
	if cache := seg.getCache(); cache != nil {
		if seg.IsFullRange() {
			cacheStrPtr(&cache.cachedWildcardString, &segmentWildcardStr)
		} else if isStandardRangeString && rangeLower == seg.getSegmentValue() && rangeUpper == seg.getUpperSegmentValue() {
			cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:upperStringEndIndex] })
		}
	}
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (seg *ipAddressSegmentInternal) GetBitCount() BitCount {
	return seg.addressSegmentInternal.GetBitCount()
}

// GetByteCount returns the number of bytes required for each value comprising this address item.
func (seg *ipAddressSegmentInternal) GetByteCount() int {
	return seg.addressSegmentInternal.GetByteCount()
}

// GetValue returns the lowest value in the address segment range as a big integer.
func (seg *ipAddressSegmentInternal) GetValue() *BigDivInt {
	return seg.addressSegmentInternal.GetValue()
}

// GetUpperValue returns the highest value in the address segment range as a big integer.
func (seg *ipAddressSegmentInternal) GetUpperValue() *BigDivInt {
	return seg.addressSegmentInternal.GetUpperValue()
}

// Bytes returns the lowest value in the address segment range as a byte slice.
func (seg *ipAddressSegmentInternal) Bytes() []byte {
	return seg.addressSegmentInternal.Bytes()
}

// UpperBytes returns the highest value in the address segment range as a byte slice.
func (seg *ipAddressSegmentInternal) UpperBytes() []byte {
	return seg.addressSegmentInternal.UpperBytes()
}

// CopyBytes copies the lowest value in the address segment range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (seg *ipAddressSegmentInternal) CopyBytes(bytes []byte) []byte {
	return seg.addressSegmentInternal.CopyBytes(bytes)
}

// CopyUpperBytes copies the highest value in the address segment range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (seg *ipAddressSegmentInternal) CopyUpperBytes(bytes []byte) []byte {
	return seg.addressSegmentInternal.CopyUpperBytes(bytes)
}

// IsZero returns whether this segment matches exactly the value of zero.
func (seg *ipAddressSegmentInternal) IsZero() bool {
	return seg.addressSegmentInternal.IsZero()
}

// IncludesZero returns whether this segment includes the value of zero within its range.
func (seg *ipAddressSegmentInternal) IncludesZero() bool {
	return seg.addressSegmentInternal.IncludesZero()
}

// IsMax returns whether this segment matches exactly the maximum possible value, the value whose bits are all ones.
func (seg *ipAddressSegmentInternal) IsMax() bool {
	return seg.addressSegmentInternal.IsMax()
}

// IncludesMax returns whether this segment includes the max value, the value whose bits are all ones, within its range.
func (seg *ipAddressSegmentInternal) IncludesMax() bool {
	return seg.addressSegmentInternal.IncludesMax()
}

// IsFullRange returns whether the segment range includes all possible values for its bit length.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (seg *ipAddressSegmentInternal) IsFullRange() bool {
	return seg.addressSegmentInternal.IsFullRange()
}

// ContainsPrefixBlock returns whether the division range includes
// the block of values for the given prefix length.
func (seg *ipAddressSegmentInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return seg.addressSegmentInternal.ContainsPrefixBlock(prefixLen)
}

// IsSinglePrefix determines if the segment has a single prefix value for the given prefix length.
// You can call GetPrefixCountLen to get the count of prefixes.
func (seg *ipAddressSegmentInternal) IsSinglePrefix(divisionPrefixLength BitCount) bool {
	return seg.addressSegmentInternal.IsSinglePrefix(divisionPrefixLength)
}

// PrefixContains returns whether the prefix values in
// the prefix of the given segment are also prefix values in this segment.
// It returns whether the prefix of this segment contains the prefix of the given segment.
func (seg *ipAddressSegmentInternal) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.addressSegmentInternal.PrefixContains(other, prefixLength)
}

// PrefixEqual returns whether the prefix bits of this segment match the same bits of the given segment.
// It returns whether the two segments share the same range of prefix values using the given prefix length.
func (seg *ipAddressSegmentInternal) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.addressSegmentInternal.PrefixEqual(other, prefixLength)
}

// GetSegmentValue returns the lower value of the segment value range.
func (seg *ipAddressSegmentInternal) GetSegmentValue() SegInt {
	return seg.addressSegmentInternal.GetSegmentValue()
}

// GetUpperSegmentValue returns the upper value of the segment value range.
func (seg *ipAddressSegmentInternal) GetUpperSegmentValue() SegInt {
	return seg.addressSegmentInternal.GetUpperSegmentValue()
}

// Matches returns true if the segment range matches the given single value.
func (seg *ipAddressSegmentInternal) Matches(value SegInt) bool {
	return seg.addressSegmentInternal.Matches(value)
}

// MatchesWithMask applies the mask to this segment and then compares the result with the given value,
// returning true if the range of the resulting segment matches that single value.
func (seg *ipAddressSegmentInternal) MatchesWithMask(value, mask SegInt) bool {
	return seg.addressSegmentInternal.MatchesWithMask(value, mask)
}

// MatchesValsWithMask applies the mask to this segment and then compares the result with the given values,
// returning true if the range of the resulting segment matches the given range.
func (seg *ipAddressSegmentInternal) MatchesValsWithMask(lowerValue, upperValue, mask SegInt) bool {
	return seg.addressSegmentInternal.MatchesValsWithMask(lowerValue, upperValue, mask)
}

// GetPrefixCountLen returns the count of the number of distinct prefix values for the given prefix length in the range of values of this segment.
func (seg *ipAddressSegmentInternal) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return seg.addressSegmentInternal.GetPrefixCountLen(segmentPrefixLength)
}

// GetPrefixValueCountLen returns the same value as GetPrefixCountLen as an integer.
func (seg *ipAddressSegmentInternal) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return seg.addressSegmentInternal.GetPrefixValueCountLen(segmentPrefixLength)
}

// GetValueCount returns the same value as GetCount as an integer.
func (seg *ipAddressSegmentInternal) GetValueCount() SegIntCount {
	return seg.addressSegmentInternal.GetValueCount()
}

// GetMaxValue gets the maximum possible value for this type or version of segment,
// determined by the number of bits.
//
// For the highest range value of this particular segment, use GetUpperSegmentValue.
func (seg *ipAddressSegmentInternal) GetMaxValue() SegInt {
	return seg.addressSegmentInternal.GetMaxValue()
}

// TestBit returns true if the bit in the lower value of this segment at the given index is 1, where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this section.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (seg *ipAddressSegmentInternal) TestBit(n BitCount) bool {
	return seg.addressSegmentInternal.TestBit(n)
}

// IsOneBit returns true if the bit in the lower value of this segment at the given index is 1, where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (seg *ipAddressSegmentInternal) IsOneBit(segmentBitIndex BitCount) bool {
	return seg.addressSegmentInternal.IsOneBit(segmentBitIndex)
}

func (seg *ipAddressSegmentInternal) toIPAddressSegment() *IPAddressSegment {
	return (*IPAddressSegment)(unsafe.Pointer(seg))
}

// IPAddressSegment represents a single IP address segment.
// An IP segment contains a single value or a range of sequential values,
// a prefix length, and has an assigned bit length.
//
// For IPv4, segments consist of 1 byte.
// For IPv6, they consist of 2 bytes.
//
// IPAddressSegment objects are immutable and therefore concurrency-safe.
//
// For more details about segments, see AddressSegment.
type IPAddressSegment struct {
	ipAddressSegmentInternal
}

// IsMultiple returns whether this segment represents multiple values.
func (seg *IPAddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

// Contains returns whether this is same type and version as
// the given segment and whether it contains all values in the given segment.
func (seg *IPAddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToSegmentBase() == nil
	}
	return seg.contains(other)
}

// GetCount returns a count of possible distinct values for the given item.
// If multiple values are not represented, the count is 1.
//
// For example, a segment with a range of values 3-7 has a count of 5.
//
// If you want to know if the count is greater than 1, use IsMultiple.
func (seg *IPAddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

// Equal returns whether the given segment is equal to this segment.
// Two segments are equal if they match:
//   - type/version IPv4, IPv6
//   - value range
//
// Prefix lengths is ignored.
func (seg *IPAddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToDiv() == nil
		//return seg.getAddrType() == zeroType && other.(StandardDivisionType).ToDiv() == nil
	}
	return seg.equal(other)
}

// ContainsPrefixBlock returns whether the division range includes
// the block of values for the given prefix length.
func (seg *IPAddressSegment) ContainsPrefixBlock(divisionPrefixLen BitCount) bool {
	return seg.containsPrefixBlock(divisionPrefixLen)
}

// IsPrefixed returns whether this section has an associated prefix length.
func (seg *IPAddressSegment) IsPrefixed() bool {
	return seg != nil && seg.isPrefixed()
}

// IsIPv4 returns true if this segment originated as an IPv4 segment.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (seg *IPAddressSegment) IsIPv4() bool {
	return seg != nil && seg.matchesIPv4Segment()
}

// IsIPv6 returns true if this segment originated as an IPv6 segment.
// If so, use ToIPv6 to convert back to the IPv6-specific type.
func (seg *IPAddressSegment) IsIPv6() bool {
	return seg != nil && seg.matchesIPv6Segment()
}

// ToSegmentBase converts to AddressSegment, a polymorphic type used with all address segments.
// The reverse conversion can then be convert with ToIP.
//
// ToSegmentBase can be called with a nil receiver,
// allowing this method to be used in a chain with methods that can return a nil pointer.
func (seg *IPAddressSegment) ToSegmentBase() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

// ToDiv converts to AddressDivision, a polymorphic type used with all address segments and divisions.
// The reverse conversion can then be performed using ToIP.
//
// ToDiv can be called with a nil receiver,
// allowing this method to be used in a chain with methods that can return a nil pointer.
func (seg *IPAddressSegment) ToDiv() *AddressDivision {
	return seg.ToSegmentBase().ToDiv()
}

// GetWildcardString produces a normalized string to represent the segment, favouring wildcards and range characters while ignoring any network prefix length.
// The explicit range of a range-valued segment will be printed.
//
// The string returned is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and the bit-length can be deduced from the context.
// The String method produces strings more appropriate when no context is provided.
func (seg *IPAddressSegment) GetWildcardString() string {
	if seg == nil {
		return nilString()
	}
	return seg.getWildcardString()
}
