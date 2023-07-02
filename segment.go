package goip

const SegIntSize = 32 // must match the bit count of SegInt

// SegInt is an integer type for holding generic address segment values.
// It is at least as large as all address segment values: [IPv6SegInt], [IPv4SegInt], [MACSegInt].
//
// Must be at least uint16 to handle IPv6, at least 32 to handle single-segment IPv4, and no larger than 64 since bits.TrailingZeros64 is used.
// IP address segment code uses bits.TrailingZeros32 and bits.LeadingZeros32, so it cannot be larger than 32.
type SegInt = uint32

type SegIntCount = uint64 // (max value of SegInt) + 1

type segderiver interface {
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues
}

type segmentValues interface {
	// getSegmentValue gets the lower value for a segment
	getSegmentValue() SegInt
	// getUpperSegmentValue gets the upper value for a segment
	getUpperSegmentValue() SegInt
}

type addressSegmentInternal struct {
	addressDivisionInternal
}

// GetSegmentValue returns the lower value of the range of segment values.
func (seg *addressSegmentInternal) GetSegmentValue() SegInt {
	vals := seg.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getSegmentValue()
}

func (seg *addressSegmentInternal) equal(other AddressSegmentType) bool {
	if other == nil || other.ToSegmentBase() == nil {
		return false
	}

	if seg.isMultiple() {
		if other.IsMultiple() {
			matches, _ := seg.matchesStructure(other)
			otherDivision := other.ToSegmentBase()
			return matches && segValsSame(seg.getSegmentValue(), otherDivision.getSegmentValue(),
				seg.getUpperSegmentValue(), otherDivision.getUpperSegmentValue())
		} else {
			return false
		}
	} else if other.IsMultiple() {
		return false
	}

	matches, _ := seg.matchesStructure(other)
	otherDivision := other.ToSegmentBase()
	return matches && segValSame(seg.GetSegmentValue(), otherDivision.GetSegmentValue())
}

// PrefixEqual returns whether the prefix bits of a given segment match the same bits of that segment.
// Returns whether the two segments have the same range of prefix values for a given prefix length.
func (seg *addressSegmentInternal) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	prefixLength = checkBitCount(prefixLength, seg.GetBitCount())
	shift := seg.GetBitCount() - prefixLength
	if shift <= 0 {
		return seg.GetSegmentValue() == other.GetSegmentValue() && seg.GetUpperSegmentValue() == other.GetUpperSegmentValue()
	}
	return (other.GetSegmentValue()>>uint(shift)) == (seg.GetSegmentValue()>>uint(shift)) &&
		(other.GetUpperSegmentValue()>>uint(shift)) == (seg.GetUpperSegmentValue()>>uint(shift))
}

// GetUpperSegmentValue returns the upper value of the range of segment values.
func (seg *addressSegmentInternal) GetUpperSegmentValue() SegInt {
	vals := seg.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperSegmentValue()
}

// Matches returns true if the range of the segment matches the specified single value.
func (seg *addressSegmentInternal) Matches(value SegInt) bool {
	return seg.matches(DivInt(value))
}

// MatchesWithMask applies a mask to a given segment and then compares the result to the given value,
// returning true if the range of the resulting segment matches that single value.
func (seg *addressSegmentInternal) MatchesWithMask(value, mask SegInt) bool {
	return seg.matchesWithMask(DivInt(value), DivInt(mask))
}

// MatchesValsWithMask applies a mask to a given segment and then compares the result to the given values,
// returning true if the range of the resulting segment matches the given range.
func (seg *addressSegmentInternal) MatchesValsWithMask(lowerValue, upperValue, mask SegInt) bool {
	return seg.matchesValsWithMask(DivInt(lowerValue), DivInt(upperValue), DivInt(mask))
}

// GetValueCount returns the same value as GetCount as an integer.
func (seg *addressSegmentInternal) GetValueCount() SegIntCount {
	return uint64(seg.GetUpperSegmentValue()-seg.GetSegmentValue()) + 1
}

// GetMaxValue gets the maximum possible value for a given segment type or version, determined by the number of bits.
// Use GetUpperSegmentValue to get the highest range value of that particular segment.
func (seg *addressSegmentInternal) GetMaxValue() SegInt {
	return ^(^SegInt(0) << uint(seg.GetBitCount()))
}

// TestBit returns true if the bit in the lowest value of this segment by the given index is 1,
// where index 0 refers to the least significant bit.
// In other words, it calculates (bits & (1 << n) != 0), using the lowest value of that section.
// TestBit panics if n < 0, or if it matches or exceeds the number of bits of this item.
func (seg *addressSegmentInternal) TestBit(n BitCount) bool {
	value := seg.GetSegmentValue()
	if n < 0 || n > seg.GetBitCount() {
		panic("invalid bit index")
	}
	return (value & (1 << uint(n))) != 0
}

// IsOneBit returns true if the bit in the lowest value of this segment by the given index is 1,
// where index 0 refers to the most significant bit.
// IsOneBit will cause a panic if bitIndex is less than zero,
// or if it is larger than the number of bits of this item.
func (seg *addressSegmentInternal) IsOneBit(segmentBitIndex BitCount) bool {
	value := seg.GetSegmentValue()
	bitCount := seg.GetBitCount()
	if segmentBitIndex < 0 || segmentBitIndex > seg.GetBitCount() {
		panic("invalid bit index")
	}
	return (value & (1 << uint(bitCount-(segmentBitIndex+1)))) != 0
}

func (seg *addressSegmentInternal) getDefaultSegmentWildcardString() string {
	return SegmentWildcardStr
}

func segValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func segValSame(oneVal, twoVal SegInt) bool {
	return oneVal == twoVal
}
