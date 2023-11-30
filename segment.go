package goip

import (
	"math/big"
	"math/bits"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

const SegIntSize = 32 // must match the bit count of SegInt

var (
	// wildcards differ, for divs we use only range since div size not implicit, here we use both range and *
	hexParamsSeg     = new(address_string.IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).ToOptions()
	decimalParamsSeg = new(address_string.IPStringOptionsBuilder).SetRadix(10).ToOptions()
)

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

// CopyBytes copies the lowest value in the address segment range to a byte slice.
// If the value can fit in a given slice, it is copied to that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned along with the value.
func (seg *addressSegmentInternal) CopyBytes(bytes []byte) []byte {
	return seg.addressDivisionInternal.CopyBytes(bytes)
}

// CopyUpperBytes copies the highest value in the address segment range to a byte slice.
// If the value can fit in a given slice, it is copied to that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned along with the value.
func (seg *addressSegmentInternal) CopyUpperBytes(bytes []byte) []byte {
	return seg.addressDivisionInternal.CopyUpperBytes(bytes)
}

// IsZero returns whether the segment is exactly zero.
func (seg *addressSegmentInternal) IsZero() bool {
	return seg.addressDivisionInternal.IsZero()
}

// IncludesZero returns whether the segment includes a value of zero in its range.
func (seg *addressSegmentInternal) IncludesZero() bool {
	return seg.addressDivisionInternal.IncludesZero()
}

// IsMax returns whether the segment exactly matches the maximum possible value - a value whose bits are all one.
func (seg *addressSegmentInternal) IsMax() bool {
	return seg.addressDivisionInternal.IsMax()
}

// IncludesMax returns whether the segment includes the maximum value, a value whose bits are all one, in its range.
func (seg *addressSegmentInternal) IncludesMax() bool {
	return seg.addressDivisionInternal.IncludesMax()
}

// IsFullRange returns whether the segment range includes all possible values for its bit length.
// This is true if and only if both IncludesZero and IncludesMax return true.
func (seg *addressSegmentInternal) IsFullRange() bool {
	return seg.addressDivisionInternal.IsFullRange()
}

// ContainsPrefixBlock returns whether the segment range includes a values block for a given prefix length.
func (seg *addressSegmentInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return seg.addressDivisionInternal.ContainsPrefixBlock(prefixLen)
}

// IsSinglePrefix determines whether a segment has a single prefix value for a given prefix length.
// You can call GetPrefixCountLen to get the number of prefixes.
func (seg *addressSegmentInternal) IsSinglePrefix(divisionPrefixLength BitCount) bool {
	return seg.addressDivisionInternal.IsSinglePrefix(divisionPrefixLength)
}

func (seg *addressSegmentInternal) sameTypeContains(otherSeg *AddressSegment) bool {
	return otherSeg.GetSegmentValue() >= seg.GetSegmentValue() &&
		otherSeg.GetUpperSegmentValue() <= seg.GetUpperSegmentValue()
}

func (seg *addressSegmentInternal) contains(other AddressSegmentType) bool {
	if other == nil {
		return true
	}

	otherSeg := other.ToSegmentBase()
	if seg.toAddressSegment() == otherSeg || otherSeg == nil {
		return true
	} else if matchesStructure, _ := seg.matchesStructure(other); matchesStructure {
		return seg.sameTypeContains(otherSeg)
	}

	return false
}

// PrefixContains returns whether the prefix values in this segment prefix are also prefix values in this segment.
// Returns whether the prefix of this segment contains the prefix of given segment.
func (seg *addressSegmentInternal) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	prefixLength = checkBitCount(prefixLength, seg.GetBitCount())
	shift := seg.GetBitCount() - prefixLength
	if shift <= 0 {
		return seg.contains(other)
	}
	return (other.GetSegmentValue()>>uint(shift)) >= (seg.GetSegmentValue()>>uint(shift)) &&
		(other.GetUpperSegmentValue()>>uint(shift)) <= (seg.GetUpperSegmentValue()>>uint(shift))
}

func (seg *addressSegmentInternal) sameTypeEquals(other *AddressSegment) bool {
	if seg.isMultiple() {
		return other.isMultiple() && segValsSame(seg.getSegmentValue(), other.getSegmentValue(),
			seg.getUpperSegmentValue(), other.getUpperSegmentValue())
	}
	return !other.isMultiple() && seg.getSegmentValue() == other.getSegmentValue()
}

func (seg *addressSegmentInternal) toAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

// GetPrefixCountLen returns a count of the number of individual prefix values for a given prefix length in the value range of that segment.
func (seg *addressSegmentInternal) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return bigZero().SetUint64(seg.GetPrefixValueCountLen(segmentPrefixLength))
}

// GetPrefixValueCountLen returns the same value as GetPrefixCountLen as an integer.
func (seg *addressSegmentInternal) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return getPrefixValueCount(seg.toAddressSegment(), segmentPrefixLength)
}

func (seg *addressSegmentInternal) getLower() *AddressSegment {
	if !seg.isMultiple() {
		return seg.toAddressSegment()
	}

	var newVals divisionValues
	vals := seg.divisionValues
	if vals != nil {
		newVals = seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetSegmentValue(), seg.getDivisionPrefixLength())
	}

	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) getUpper() *AddressSegment {
	if !seg.isMultiple() {
		return seg.toAddressSegment()
	}

	var newVals divisionValues
	vals := seg.divisionValues
	if vals != nil {
		newVals = seg.deriveNewMultiSeg(seg.GetUpperSegmentValue(), seg.GetUpperSegmentValue(), seg.getDivisionPrefixLength())
	}

	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) segmentIterator(segPrefLen PrefixLen, isPrefixIterator, isBlockIterator bool) Iterator[*AddressSegment] {
	vals := seg.divisionValues
	if vals == nil {
		return segIterator(seg,
			0,
			0,
			0,
			nil,
			nil,
			false,
			false,
		)
	}
	return segIterator(seg,
		seg.getSegmentValue(),
		seg.getUpperSegmentValue(),
		seg.getBitCount(),
		vals,
		segPrefLen,
		isPrefixIterator,
		isBlockIterator,
	)
}

func (seg *addressSegmentInternal) iterator() Iterator[*AddressSegment] {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), false, false)
}

func (seg *addressSegmentInternal) identityIterator() Iterator[*AddressSegment] {
	return &singleSegmentIterator{original: seg.toAddressSegment()}
}

func (seg *addressSegmentInternal) prefixBlockIterator() Iterator[*AddressSegment] {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), true, true)
}

func (seg *addressSegmentInternal) prefixIterator() Iterator[*AddressSegment] {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), true, false)
}

func (seg *addressSegmentInternal) prefixedBlockIterator(segPrefLen BitCount) Iterator[*AddressSegment] {
	return seg.segmentIterator(cacheBitCount(segPrefLen), true, true)
}

func (seg *addressSegmentInternal) prefixedIterator(segPrefLen BitCount) Iterator[*AddressSegment] {
	return seg.segmentIterator(cacheBitCount(segPrefLen), true, false)
}

func (seg *addressSegmentInternal) withoutPrefixLen() *AddressSegment {
	if seg.isPrefixed() {
		return createAddressDivision(seg.derivePrefixed(nil)).ToSegmentBase()
	}
	return seg.toAddressSegment()
}

func (seg *addressSegmentInternal) reverseMultiValSeg(perByte bool) (res *AddressSegment, err address_error.IncompatibleAddressError) {
	if isReversible := seg.isReversibleRange(perByte); isReversible {
		res = seg.withoutPrefixLen()
		return
	}
	err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
	return
}

// ReverseBits returns a segment with the bits reversed.
//
// If this segment represents a range of values that cannot be reversed, then this returns an error.
//
// To be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
// Otherwise the result is not contiguous and thus cannot be represented by a sequential range of values.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (seg *addressSegmentInternal) ReverseBits(perByte bool) (res *AddressSegment, err address_error.IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg.toAddressSegment()
		return
	}

	if seg.isMultiple() {
		return seg.reverseMultiValSeg(perByte)
	}

	var val SegInt
	oldVal := seg.GetSegmentValue()
	byteCount := seg.GetByteCount()
	switch byteCount {
	case 1:
		val = SegInt(reverseUint8(uint8(oldVal)))
	case 2:
		val = SegInt(reverseUint16(uint16(oldVal)))
		if perByte {
			val = ((val & 0xff) << 8) | (val >> 8)
		}
	case 3:
		val = reverseUint32(uint32(oldVal)) >> 8
		if perByte {
			val = ((val & 0xff) << 16) | (val & 0xff00) | (val >> 16)
		}
	case 4:
		val = reverseUint32(uint32(oldVal))
		if perByte {
			val = ((val & 0xff) << 24) | (val&0xff00)<<8 | (val&0xff0000)>>8 | (val >> 24)
		}
	default: // SegInt is at most 32 bits so this default case is not possible
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}

	if oldVal == val && !seg.isPrefixed() {
		res = seg.toAddressSegment()
	} else {
		res = createAddressSegment(seg.deriveNewSeg(val, nil))
	}

	return
}

// ReverseBytes returns a segment with the bytes reversed.
//
// If this segment represents a range of values that cannot be reversed, then this returns an error.
//
// To be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
// Otherwise the result is not contiguous and thus cannot be represented by a sequential range of values.
func (seg *addressSegmentInternal) ReverseBytes() (res *AddressSegment, err address_error.IncompatibleAddressError) {
	byteCount := seg.GetByteCount()
	if byteCount <= 1 {
		res = seg.toAddressSegment()
		return
	}

	if seg.isMultiple() {
		return seg.reverseMultiValSeg(false)
	}

	var val SegInt
	oldVal := seg.GetSegmentValue()

	switch byteCount {
	case 2:
		val = ((oldVal & 0xff) << 8) | (oldVal >> 8)
	case 3:
		val = ((oldVal & 0xff) << 16) | (oldVal & 0xff00) | (oldVal >> 16)
	case 4:
		val = ((oldVal & 0xff) << 24) | (oldVal&0xff00)<<8 | (oldVal&0xff0000)>>8 | (oldVal >> 24)
	default: // SegInt is at most 32 bits so this default case is not possible
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}

	if oldVal == val && !seg.isPrefixed() {
		res = seg.toAddressSegment()
	} else {
		res = createAddressSegment(seg.deriveNewSeg(val, nil))
	}

	return
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this segment includes the block of all values for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this segment represents a single value, this returns the bit count.
func (seg *addressSegmentInternal) GetMinPrefixLenForBlock() BitCount {
	return seg.addressDivisionInternal.GetMinPrefixLenForBlock()
}

// GetPrefixLenForSingleBlock returns a prefix length for which there is only one prefix in this segment,
// and the range of values in this segment matches the block of all values for that prefix.
//
// If the range of segment values can be described this way,
// then this method returns the same value as GetMinPrefixLenForBlock.
//
// If no such prefix length exists, returns nil.
//
// If this segment represents a single value, this returns the bit count of the segment.
func (seg *addressSegmentInternal) GetPrefixLenForSingleBlock() PrefixLen {
	return seg.addressDivisionInternal.GetPrefixLenForSingleBlock()
}

func (seg *addressSegmentInternal) equalsSegment(other *AddressSegment) bool {
	matchesStructure, _ := seg.matchesStructure(other)
	return matchesStructure && seg.sameTypeEquals(other)
}

// ToNormalizedString produces a string that is consistent for all address segments of the same type and version.
// IPv4 segments use base 10, while other segment types use base 16.
func (seg *addressSegmentInternal) ToNormalizedString() string {
	stringer := func() string {
		switch seg.getDefaultTextualRadix() {
		case 10:
			return seg.toStringOpts(decimalParamsSeg)
		default:
			return seg.toStringOpts(macCompressedParams)
		}
	}

	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedNormalizedString, stringer)
		}
	}
	return stringer()
}

// AddressSegment represents a single address segment.
// A segment contains a single value or range of sequential values and has an assigned bit length.
// Segments are 1 byte for Ipv4, two bytes for Ipv6, and 1 byte for MAC addresses.
//
// There are alternative forms of dividing addresses into segments, such as dotted representation for MAC like "1111.2222.3333",
// embedded IPv4 representation for IPv6 like "f:f:f:f:f:f:f:1.2.3.4", inet_aton formats like "1.2" for IPv4, etc.
//
// The general rules are that segments are a whole number of bytes, and in a given address, all segments are the same length.
//
// When alternate forms do not follow the general rules for segments, [AddressDivision] can be used instead.
// The restriction that address divisions have the same length and an integer number of bytes does not apply to divisions.
// Divisions can be grouped using [AddressDivisionGrouping].
//
// AddressSegment objects are immutable and therefore concurrency-safe.
type AddressSegment struct {
	addressSegmentInternal
}

// Contains returns whether the given segment is the same type and version as the given segment,
// and whether it contains all the values in the given segment.
func (seg *AddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToSegmentBase() == nil
	}
	return seg.contains(other)
}

// Equal returns whether the given segment is equal to this segment.
// Two segments are equal if they match:
//   - type/version (IPv4, IPv6, MAC)
//   - value range
//
// Prefix lengths are ignored.
func (seg *AddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToDiv() == nil
	}
	return seg.equal(other)
}

// GetLower returns a segment representing only the lowest value in the range,
// which would be the same segment if it represented a single value.
func (seg *addressSegmentInternal) GetLower() *AddressSegment {
	return seg.getLower()
}

// GetUpper returns a segment representing only the highest value in the range,
// which would be the same segment if it represented a single value.
func (seg *addressSegmentInternal) GetUpper() *AddressSegment {
	return seg.getUpper()
}

// IsMultiple returns whether this segment represents multiple values.
func (seg *AddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

// GetCount returns the number of possible different values for this item.
// If no multiple values are represented, the count is 1.
// For instance, a segment with a value range of 3-7 has a count of 5.
// Use IsMultiple if you just want to know if the count is greater than 1.
func (seg *AddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

// IsIP returns true if this segment originated as an IPv4 or IPv6 segment, or an implicitly zero-valued IP segment.
// If so, use ToIP to convert back to an IP-specific type.
func (seg *AddressSegment) IsIP() bool {
	return seg != nil && seg.matchesIPSegment()
}

// IsIPv4 returns true if this segment was created as an IPv4 segment.
// If so, use ToIPv4 to convert back to IPv4-specific type.
func (seg *AddressSegment) IsIPv4() bool {
	return seg != nil && seg.matchesIPv4Segment()
}

// IsIPv6 returns true if this segment was created as an IPv6 segment.
// If so, use ToIPv6 to convert back to IPv6-specific type.
func (seg *AddressSegment) IsIPv6() bool {
	return seg != nil && seg.matchesIPv6Segment()
}

// IsMAC returns true if this segment was created as a MAC segment.
// If so, use ToMAC to convert back to MAC-specific type.
func (seg *AddressSegment) IsMAC() bool {
	return seg != nil && seg.matchesMACSegment()
}

// ToSegmentBase is an identity method that can be called with a nil receiver,
// allowing this method to be used in a chain with methods that can return a nil pointer.
func (seg *AddressSegment) ToSegmentBase() *AddressSegment {
	return seg
}

// ToDiv converts to AddressDivision, a polymorphic type used with all address segments and divisions.
// This can then be converted back with ToSegmentBase.
// ToDiv can be called with a nil receiver, allowing this method to be used in a chain with methods that may return a nil pointer.
func (seg *AddressSegment) ToDiv() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(seg))
}

// ToMAC converts to a MACAddressSegment if this segment originated as a MAC segment.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (seg *AddressSegment) ToMAC() *MACAddressSegment {
	if seg.IsMAC() {
		return (*MACAddressSegment)(seg)
	}
	return nil
}

// ToIPv4 converts to an IPv4AddressSegment if this segment originated as an IPv4 segment.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (seg *AddressSegment) ToIPv4() *IPv4AddressSegment {
	if seg.IsIPv4() {
		return (*IPv4AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

// ToIPv6 converts to an IPv6AddressSegment if this segment originated as an IPv6 segment.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (seg *AddressSegment) ToIPv6() *IPv6AddressSegment {
	if seg.IsIPv6() {
		return (*IPv6AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

// ToIP converts to an IPAddressSegment if this division originated as an IPv4 or IPv6 segment,
// or an implicitly zero-valued IP segment.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (seg *AddressSegment) ToIP() *IPAddressSegment {
	if seg.IsIP() {
		return (*IPAddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

// Iterator provides an iterator to iterate through the individual address segments of this address segment.
//
// Call IsMultiple to determine if this instance represents multiple address segments,
// or GetValueCount for the count.
func (seg *AddressSegment) Iterator() Iterator[*AddressSegment] {
	if seg == nil {
		return nilSegIterator()
	}
	return seg.iterator()
}

// GetWildcardString produces a normalized string to represent the segment,
// favouring wildcards and range characters while ignoring any network prefix length.
// The explicit range of a range-valued segment will be printed.
//
// The string returned is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and the bit-length can be deduced from the context.
// The String method produces strings more appropriate when no context is provided.
func (seg *AddressSegment) GetWildcardString() string {
	if seg == nil {
		return nilString()
	}
	return seg.getWildcardString()
}

func segsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return onePref.Equal(twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}

func segValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func segValSame(oneVal, twoVal SegInt) bool {
	return oneVal == twoVal
}

func createAddressSegment(vals divisionValues) *AddressSegment {
	return &AddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{
				addressDivisionBase{
					vals,
				},
			},
		},
	}
}

func getPrefixValueCount(segment *AddressSegment, segmentPrefixLength BitCount) SegIntCount {
	shiftAdjustment := segment.GetBitCount() - segmentPrefixLength
	if shiftAdjustment <= 0 {
		return SegIntCount(segment.GetUpperSegmentValue()) - SegIntCount(segment.GetSegmentValue()) + 1
	}
	return SegIntCount(segment.GetUpperSegmentValue()>>uint(shiftAdjustment)) - SegIntCount(segment.GetSegmentValue()>>uint(shiftAdjustment)) + 1
}

// compareSegInt returns a negative number, 0 or a positive number if integer one is less than, equal to or greater than integer two.
func compareSegInt(one, two SegInt) int {
	if one < two {
		return -1
	} else if one > two {
		return 1
	}
	return 0
}

func getSegmentPrefLen(_ AddressSegmentSeries, prefLen PrefixLen, bitsPerSegment, bitsMatchedSoFar BitCount, segment *AddressSegment) PrefixLen {
	if ipSeg := segment.ToIP(); ipSeg != nil {
		return ipSeg.GetSegmentPrefixLen()
	} else if prefLen != nil {
		result := prefLen.Len() - bitsMatchedSoFar
		if result <= bitsPerSegment {
			if result < 0 {
				result = 0
			}
			return cacheBitCount(result)
		}
	}
	return nil
}

func getMatchingBits(segment1, segment2 *AddressSegment, maxBits, bitsPerSegment BitCount) BitCount {
	if maxBits == 0 {
		return 0
	}

	val1 := segment1.getSegmentValue()
	val2 := segment2.getSegmentValue()
	xor := val1 ^ val2

	switch bitsPerSegment {
	case IPv4BitsPerSegment:
		return BitCount(bits.LeadingZeros8(uint8(xor)))
	case IPv6BitsPerSegment:
		return BitCount(bits.LeadingZeros16(uint16(xor)))
	default:
		return BitCount(bits.LeadingZeros32(xor)) - 32 + bitsPerSegment
	}
}
