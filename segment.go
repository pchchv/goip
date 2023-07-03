package goip

import "math/bits"

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

// GetLeadingBitCount returns the number of consecutive leading bits of one or zero.
// If ones is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
// This method applies only to the lowest value of the range if that segment represents multiple values.
func (seg *addressSegmentInternal) GetLeadingBitCount(ones bool) BitCount {
	extraLeading := 32 - seg.GetBitCount()
	val := seg.GetSegmentValue()

	if ones {
		//leading ones
		return BitCount(bits.LeadingZeros32(uint32(^val&seg.GetMaxValue()))) - extraLeading
	}
	// leading zeros
	return BitCount(bits.LeadingZeros32(uint32(val))) - extraLeading
}

// GetTrailingBitCount returns the number of consecutive trailing one or zero bits.
// If ones is true, it returns the number of consecutive trailing zero bits.
// Otherwise, it returns the number of consecutive trailing one bits.
// This method applies only to the lowest value of the range if that segment represents multiple values.
func (seg *addressSegmentInternal) GetTrailingBitCount(ones bool) BitCount {
	val := seg.GetSegmentValue()

	if ones {
		// trailing ones
		return BitCount(bits.TrailingZeros32(uint32(^val)))
	}

	//trailing zeros
	bitCount := uint(seg.GetBitCount())
	return BitCount(bits.TrailingZeros32(uint32(val | (1 << bitCount))))
}

// GetSegmentNetworkMask returns a value comprising of the same number of total bits as the bit length of a given segment,
// a value that represents all one-bits for a given number of bits followed by all zero-bits.
func (seg *addressSegmentInternal) GetSegmentNetworkMask(networkBits BitCount) SegInt {
	bitCount := seg.GetBitCount()
	networkBits = checkBitCount(networkBits, bitCount)
	return seg.GetMaxValue() & (^SegInt(0) << uint(bitCount-networkBits))
}

// GetSegmentHostMask returns a value comprising of the same number of total bits as the bit length of a given segment,
// a value that represents all zero-bits for a given number of bits followed by all one-bits.
func (seg *addressSegmentInternal) GetSegmentHostMask(networkBits BitCount) SegInt {
	bitCount := seg.GetBitCount()
	networkBits = checkBitCount(networkBits, bitCount)
	return ^(^SegInt(0) << uint(bitCount-networkBits))
}

func (seg *addressSegmentInternal) isReversibleRange(perByte bool) (isReversible bool) {
	// Consider the case of range bit reversing.
	// Any range that can be reversed successfully must span all bits
	// (otherwise after flipping you will get a range where the lowest bit is constant, which is impossible in any contiguous range).
	// This means that at least one value is 0xxxx and the other is 1xxxx (using 5 bits for our example).
	// This means that you should have values 01111 and 10000, since the range is continuous.
	// But if you reversing a range twice, you get the original again,
	// so the reversed range must also be reversible, so the reversed range also has 01111 and 10000.
	// This means that in both the original and reversed ranges the two patterns are also flipped, namely 00001 and 11110.
	// This means that both ranges must span from at most 1 to at least 11110.
	// However, the two remaining values, 0 and 11111, are optional because they are boundary values and remain themselves when flipped,
	// and thus have no effect on whether the reversible range is continuous.
	// Thus, the only reversible ranges are 0-11111, 0-11110, 1-11110, and 1-11111.
	// -----------------------
	// Consider the case of reversing each of the bytes of a range.
	//
	// You can apply the same argument to the top multiple byte, which means it is 0 or 1 to 254 or 255.
	// Suppose it is followed by another byte.
	// If you take the range of the upper byte and hold it constant, then reversing the next byte applies the same argument to that byte.
	// Thus, the lower byte should span from at most 1 to at least 11111110.
	// This argument also applies when the value of the upper byte is constant.
	// Thus, at any value, the lower byte must span from at most 1 to no at least 111111110.
	// So you have x 00000001-x 111111110 and y 00000001-y 111111110 and so on.
	//
	// But all bytes form a range, so you must also have values between them.
	//
	// This means that you have 1 00000001 - 1 111111110 - 10 111111110 - 11 111111110 up to x 11111110, where x is at least 11111110.
	// In all cases, the upper byte lower value is at most 1, and 1 < 10000000.
	// This means that you always have 10000000 00000000.
	// So you also have an reverse value (as argued above, for any value we have an reverse value).
	// So you always have 00000001 00000000.
	//
	// In other words, if the upper byte has a lower 0, then the full low byte must be at most 0 00000001.
	// Otherwise, if the upper byte has a lower 1, then the full bytes lower is at most 1 00000000.
	//
	// In other words, if any upper byte has a lower value 1, then all lower values to follow are 0.
	// If all upper bytes have a lower value 0, then the next byte is permitted to have a lower value 1.
	//
	// In general, any upper byte that has a lower of 1 forces the remaining lower values to be 0.
	//
	// If all upper bytes are zero, and thus the lower is at most 0 0 0 0 1, then the only remaining lower value is 0 0 0 0 0.
	// This value reverses to itself, so it is optional.
	//
	// The same argument applies to upper bounds.
	// ----------------------
	// Consider the case of reversing the bytes of a range.
	// Any range that can be reversed successfully must span all bits
	// (otherwise after flipping you will have a range where the lowest bit is constant, which is impossible in any contiguous range).
	// This means that at least one value is 0xxxxx and the other is 1xxxxx (we use 6 bits for our example and assume that each byte has 3 bits).
	// This means that you should have the values 011111 and 100000 because the range is continuous.
	// But if you reversing the range twice, you get the original again, so the reversed range must also be reversible,
	// so the reversed range also has 011111 and 100000.
	//
	// This means that both the original and the reversed also have these two bytes in each flipped, namely 111011 and 000100.
	// Thus, the range must have 000100, 011111, 100000, 111011, so it must be at least 000100 to 111011.
	// But what if the range does not have 000001?
	// Then the reversed range cannot have 001000, the byte-reversed address.
	// But we know that it spans from 000100 to 111011.
	// So the original must have 000001. What if it doesn't have 111110?
	// Then the reverse can't have 110111, a byte-reversed address.
	// But we know it's between 000100 and 111011.
	// So the original must have 111110.
	// So it must be in the range 000001 to 111110.
	// That leaves only the values 000000 and 111111.
	// But again, the two remaining values are optional, because the byte-reverse to themselves.
	// Thus, in the case of byte-reverse, we have the same potential ranges as in the case of bit-reverse: 0-111111, 0-111110, 1-111110, and 1-111111.
	if perByte {
		byteCount := seg.GetByteCount()
		bitCount := seg.GetBitCount()
		val := seg.GetSegmentValue()
		upperVal := seg.GetUpperSegmentValue()
		for i := 1; i <= byteCount; i++ {
			bitShift := i << 3
			shift := bitCount - BitCount(bitShift)
			byteVal := val >> uint(shift)
			upperByteVal := upperVal >> uint(shift)
			if byteVal != upperByteVal {
				if byteVal > 1 || upperByteVal < 254 {
					return false
				}
				i++
				if i <= byteCount {
					lowerIsZero := byteVal == 1
					upperIsMax := upperByteVal == 254
					for {
						bitShift = i << 3
						shift = bitCount - BitCount(bitShift)
						byteVal = val >> uint(shift)
						upperByteVal = upperVal >> uint(shift)
						if lowerIsZero {
							if byteVal != 0 {
								return
							}
						} else {
							if byteVal > 1 {
								return
							}
							lowerIsZero = byteVal == 1
						}
						if upperIsMax {
							if upperByteVal != 255 {
								return
							}
						} else {
							if upperByteVal < 254 {
								return
							}
							upperIsMax = upperByteVal == 254
						}
						i++
						if i > byteCount {
							break
						}
					}
				}
				return true
			}
		}
		return true
	}
	isReversible = seg.GetSegmentValue() <= 1 && seg.GetUpperSegmentValue() >= seg.GetMaxValue()-1
	return
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (seg *addressSegmentInternal) GetBitCount() BitCount {
	return seg.addressDivisionInternal.GetBitCount()
}

// GetByteCount returns the number of bytes required for each value that makes up the given address element.
func (seg *addressSegmentInternal) GetByteCount() int {
	return seg.addressDivisionInternal.GetByteCount()
}

// GetValue returns the lowest value in the address segment range as a big integer.
func (seg *addressSegmentInternal) GetValue() *BigDivInt {
	return seg.addressDivisionInternal.GetValue()
}

// GetUpperValue returns the highest value in the address segment range as a big integer.
func (seg *addressSegmentInternal) GetUpperValue() *BigDivInt {
	return seg.addressDivisionInternal.GetUpperValue()
}

// Bytes returns the lowest value in the address segment range as a byte slice.
func (seg *addressSegmentInternal) Bytes() []byte {
	return seg.addressDivisionInternal.Bytes()
}

// UpperBytes returns the highest value in the address segment range as a byte slice.
func (seg *addressSegmentInternal) UpperBytes() []byte {
	return seg.addressDivisionInternal.UpperBytes()
}

func segValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func segValSame(oneVal, twoVal SegInt) bool {
	return oneVal == twoVal
}
