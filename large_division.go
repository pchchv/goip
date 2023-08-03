package goip

import (
	"bytes"
	"math/big"
	"unsafe"
)

var _ divisionValues = &largeDivValues{}

type BigDivInt = big.Int

type addressLargeDivInternal struct {
	addressDivisionBase
	defaultRadix *BigDivInt
}

func (div *addressLargeDivInternal) getDefaultRadix() int {
	rad := div.defaultRadix
	if rad == nil {
		return 16 // use same default as other divisions when zero div
	}
	return int(rad.Int64())
}

func (div *addressLargeDivInternal) toLargeAddressDivision() *IPAddressLargeDivision {
	return (*IPAddressLargeDivision)(unsafe.Pointer(div))
}

// getDefaultTextualRadix returns the default radix for textual representations of divisions.
func (div *addressLargeDivInternal) getDefaultTextualRadix() int {
	if div.divisionValues == nil || div.defaultRadix == nil {
		return 16 // use same default as other divisions when zero div
	}
	return int(div.defaultRadix.Int64())
}

func (div *addressLargeDivInternal) getLargeDivValues() *largeDivValues {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.(*largeDivValues)
}

// getBigDefaultTextualRadix returns the default radix for textual representations of divisions.
func (div *addressLargeDivInternal) getBigDefaultTextualRadix() *big.Int {
	if div.divisionValues == nil || div.defaultRadix == nil {
		return bigSixteen() // use same default as other divisions when zero div
	}
	return div.defaultRadix
}

// IPAddressLargeDivision represents an arbitrary bit size division in an address or address division grouping.
// It can contain a single value or a range of consecutive values and has an assigned bit length.
// Like all address components, it is immutable.
type IPAddressLargeDivision struct {
	addressLargeDivInternal
}

// IsMultiple returns true if the given division represents a consecutive range of values or a single value.
func (div *IPAddressLargeDivision) IsMultiple() bool {
	return div != nil && div.isMultiple()
}

// IsPrefixed returns whether the given division has a prefix length associated with it.
// If so, the prefix length is given by GetDivisionPrefixLen()
func (div *IPAddressLargeDivision) IsPrefixed() bool {
	return div.GetDivisionPrefixLen() != nil
}

// GetDivisionPrefixLen returns the network prefix for the division.
// For an address like "1.2.0.0/16", the network prefix is 16.
// When it comes to each address subdivision or segment, the subdivision prefix is the prefix obtained by applying an address or partition prefix.
// For example, consider the address "1.2.0.0/20."
// The first segment has no prefix because the address prefix 20 is beyond the 8 bits in the first segment, it is not even applied to the segment.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which are in the second segment, it also does not apply to this segment.
// The third segment is prefixed with 4 because address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network portion of the address or segment.
// The last segment is prefixed with 0 because no bits are part of the network portion of the address or segment.
// The following division prefixes apply throughout the address: nil ... nil (1 to the bit length of the segment) 0 ... 0.
// If the division has no prefix, nil is returned.
func (div *IPAddressLargeDivision) GetDivisionPrefixLen() PrefixLen {
	return div.getDivisionPrefixLength()
}

// GetPrefixLen returns the network prefix for the unit.
// For an address like "1.2.0.0/16", the network prefix is 16.
// When it comes to each address subdivision or segment, the prefix for the subdivision is the prefix obtained when the address or partition prefix is applied.
// For example, consider the address "1.2.0.0/20".
// The first segment has no prefix because the address prefix 20 is beyond the 8 bits in the first segment, it is not even applied to the segment.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which are in the second segment, it also does not apply to this segment.
// The third segment is prefixed with 4 because address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network portion of the address or segment.
// The last segment is prefixed with 0 because no bits are part of the network portion of the address or segment.
// The following division prefixes apply throughout the address: nil ... nil (1 to the bit length of the segment) 0 ... 0.
// If the segment has no prefix, nil is returned.
func (div *IPAddressLargeDivision) GetPrefixLen() PrefixLen {
	return div.getDivisionPrefixLength()
}

func (div *IPAddressLargeDivision) isNil() bool {
	return div == nil
}

// IsSinglePrefix returns true if the division value range spans
// just a single prefix value for the given prefix length.
func (div *IPAddressLargeDivision) IsSinglePrefix(divisionPrefixLen BitCount) bool {
	lower, upper := div.getValue(), div.getUpperValue()
	bitCount := div.GetBitCount()
	divisionPrefixLen = checkBitCount(divisionPrefixLen, bitCount)
	shift := uint(bitCount - divisionPrefixLen)
	var one, two big.Int
	return one.Rsh(lower, shift).Cmp(two.Rsh(upper, shift)) == 0
}

func (div *IPAddressLargeDivision) getBigRadix(radix int) *big.Int {
	defaultRadix := div.getDefaultTextualRadix()
	if defaultRadix == radix {
		return div.getBigDefaultTextualRadix()
	}
	return big.NewInt(int64(radix))
}

func (div *IPAddressLargeDivision) getRangeDigitCount(radix int) int {
	if !div.IsMultiple() {
		return 0
	}

	var quotient, upperQuotient, remainder big.Int
	val, upperVal := div.getValue(), div.getUpperValue()
	count := 1
	bigRadix := big.NewInt(int64(radix))
	bigUpperDigit := big.NewInt(int64(radix - 1))

	for {
		quotient.QuoRem(val, bigRadix, &remainder)
		if bigIsZero(&remainder) {
			upperQuotient.QuoRem(upperVal, bigRadix, &remainder)
			if remainder.CmpAbs(bigUpperDigit) == 0 {
				val, upperVal = &quotient, &upperQuotient
				if val.CmpAbs(upperVal) == 0 {
					return count
				} else {
					count++
					continue
				}
			}
		}
		return 0
	}
}

// IsPrefixBlock returns whether the division has a prefix length and
// the division range includes the block of values for that prefix length.
// If the prefix length matches the bit count, this returns true.
func (div *IPAddressLargeDivision) IsPrefixBlock() bool {
	return div.getLargeDivValues().isPrefixBlock
}

// IsSinglePrefixBlock returns whether the division range matches
// the block of values for its prefix length
func (div *IPAddressLargeDivision) IsSinglePrefixBlock() bool {
	return *div.getLargeDivValues().cache.isSinglePrefBlock
}

// GetValue returns the lowest value in the address division range as a big integer.
func (div *IPAddressLargeDivision) GetValue() *BigDivInt {
	return new(big.Int).Set(div.addressLargeDivInternal.GetValue())
}

// GetUpperValue returns the highest value in the address division range as a big integer.
func (div *IPAddressLargeDivision) GetUpperValue() *BigDivInt {
	return new(big.Int).Set(div.addressLargeDivInternal.GetUpperValue())
}

// GetCount returns the count of possible distinct values for this division.
// If not representing multiple values, the count is 1.
//
// For example, a division with the value range of 3-7 has count 5.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (div *IPAddressLargeDivision) GetCount() *big.Int {
	if div == nil {
		return bigZero()
	}
	return div.getCount()
}

// ContainsPrefixBlock returns whether the division range includes
// the block of values for the given prefix length.
func (div *IPAddressLargeDivision) ContainsPrefixBlock(prefixLen BitCount) bool {
	bitCount := div.GetBitCount()

	if prefixLen <= 0 {
		return div.IsFullRange()
	} else if prefixLen >= bitCount {
		return true
	}

	lower, upper := div.getValue(), div.getUpperValue()
	return testBigRange(lower, upper, upper, bitCount, prefixLen)
}

// ContainsSinglePrefixBlock returns whether the division range matches exactly
// the block of values for the given prefix length and
// has just a single prefix for that prefix length.
func (div *IPAddressLargeDivision) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	bitCount := div.GetBitCount()
	prefixLen = checkBitCount(prefixLen, bitCount)
	if prefixLen == 0 {
		return div.IsFullRange()
	}

	lower, upper := div.getValue(), div.getUpperValue()
	return testBigRange(lower, lower, upper, bitCount, prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this division includes the block of all values for that prefix length.
//
// If the entire range can be described in this way, this method returns, the same value as GetPrefixLenForSingleBlock.
//
// This block can have a single prefix or multiple possible prefix values for the returned prefix length.
// To avoid the case of multiple prefix values, use GetPrefixLenForSingleBlock.
//
// If this division represents a single value, a bit count is returned.
func (div *IPAddressLargeDivision) GetMinPrefixLenForBlock() BitCount {
	result := div.GetBitCount()
	if div.IsMultiple() {
		lower, upper := div.getValue(), div.getUpperValue()
		lowerZeros := lower.TrailingZeroBits()
		if lowerZeros != 0 {
			var upperNot big.Int
			upperOnes := upperNot.Not(upper).TrailingZeroBits()
			if upperOnes != 0 {
				prefixedBitCount := BitCount(umin(lowerZeros, upperOnes))
				result -= prefixedBitCount
			}
		}
	}
	return result
}

// GetPrefixLenForSingleBlock returns a prefix length for which there is only one prefix in a given division,
// and the range of values in that division is the same as the block of all values for that prefix.
//
// If the range of division values can be described in this way,
// this method returns, the same value as GetMinPrefixLenForBlock.
//
// If no such prefix length exists, returns nil.
//
// If this division is a single value, this returns the bit count of the segment.
func (div *IPAddressLargeDivision) GetPrefixLenForSingleBlock() PrefixLen {
	prefLen := div.GetMinPrefixLenForBlock()
	bitCount := div.GetBitCount()

	if prefLen == bitCount {
		if !div.IsMultiple() {
			result := PrefixBitCount(prefLen)
			return &result
		}
	} else {
		lower, upper := div.getValue(), div.getUpperValue()
		shift := uint(bitCount - prefLen)
		var one, two big.Int
		if one.Rsh(lower, shift).Cmp(two.Rsh(upper, shift)) == 0 {
			result := PrefixBitCount(prefLen)
			return &result
		}
	}
	return nil
}

func (div *IPAddressLargeDivision) getMaxDigitCount() int {
	var maxValue *BigDivInt
	rad := div.getDefaultTextualRadix()
	bc := div.GetBitCount()
	vals := div.getLargeDivValues()

	if vals == nil {
		maxValue = bigZeroConst()
	} else {
		maxValue = vals.maxValue
	}

	return getBigMaxDigitCount(rad, bc, maxValue)
}

type largeDivValues struct {
	bitCount         BitCount
	value            *BigDivInt
	upperValue       *BigDivInt // always points to value when single-valued
	maxValue         *BigDivInt
	upperValueMasked *BigDivInt
	isPrefixBlock    bool // note that isSinglePrefBlock is in the divCache
	isMult           bool
	prefLen          PrefixLen
	cache            divCache
}

func (div *largeDivValues) getBitCount() BitCount {
	return div.bitCount
}

func (div *largeDivValues) getByteCount() int {
	return (int(div.getBitCount()) + 7) >> 3
}

func (div *largeDivValues) getDivisionPrefixLength() PrefixLen {
	return div.prefLen
}

// For internal use.
// Returns a cached value, so it cannot be changed or returned to external callers.
// The only place to clone is the GetValue() and GetUpperValue() methods, which return elsewhere
func (div *largeDivValues) getValue() *BigDivInt {
	return div.value
}

// For internal use.
// Returns a cached value, so it cannot be changed or returned to external callers.
// The only place to clone is the GetValue() and GetUpperValue() methods, which return elsewhere
func (div *largeDivValues) getUpperValue() *BigDivInt {
	return div.upperValue
}

func (div *largeDivValues) includesMax() bool {
	return div.upperValue.Cmp(div.maxValue) == 0
}

func (div *largeDivValues) isMultiple() bool {
	return div.isMult
}

func (div *largeDivValues) calcBytesInternal() ([]byte, []byte) {
	return div.value.Bytes(), div.upperValue.Bytes()
}

func (div *largeDivValues) bytesInternal(upper bool) []byte {
	if upper {
		return div.upperValue.Bytes()
	}
	return div.value.Bytes()
}

func (div *largeDivValues) getCache() *divCache {
	return &div.cache
}

func (div *largeDivValues) getDivisionValue() DivInt {
	return DivInt(div.value.Uint64())
}

func (div *largeDivValues) getUpperDivisionValue() DivInt {
	return DivInt(div.upperValue.Uint64())
}

func (div *largeDivValues) getSegmentValue() SegInt {
	return SegInt(div.value.Uint64())
}

func (div *largeDivValues) getUpperSegmentValue() SegInt {
	return SegInt(div.upperValue.Uint64())
}

func (div *largeDivValues) getAddrType() addrType {
	return zeroType
}

func (div *largeDivValues) includesZero() bool {
	return bigIsZero(div.value)
}

func (div *largeDivValues) getCount() *big.Int {
	var res big.Int
	return res.Sub(div.upperValue, div.value).Add(&res, bigOneConst())
}

func (div *largeDivValues) derivePrefixed(prefLen PrefixLen) divisionValues {
	return newLargeDivValuesUnchecked(div.value, div.upperValue, div.maxValue, div.isMult, prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(DivInt(val), DivInt(upperVal), prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(val, upperVal, prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(DivInt(val), DivInt(val), prefLen, div.bitCount)
}

func newLargeDivValuesUnchecked(value, upperValue, maxValue *BigDivInt, isMult bool, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	var isSinglePrefBlock bool
	result := &largeDivValues{
		prefLen:    prefLen,
		bitCount:   bitCount,
		value:      value,
		upperValue: upperValue,
		maxValue:   maxValue,
		isMult:     isMult,
	}
	result.isPrefixBlock, isSinglePrefBlock, result.upperValueMasked =
		setCachedPrefixValues(result.value, result.upperValue, result.maxValue, prefLen, bitCount)

	if isSinglePrefBlock {
		result.cache.isSinglePrefBlock = &trueVal
	} else {
		result.cache.isSinglePrefBlock = &falseVal
	}

	return result
}

func newLargeDivValuesDivIntUnchecked(value, upperValue DivInt, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{
		prefLen:  prefLen,
		bitCount: bitCount,
	}
	val := new(big.Int).SetUint64(uint64(value))

	if value == upperValue {
		result.value, result.upperValue = val, val
	} else {
		result.isMult = true
		result.value, result.upperValue = val, new(big.Int).SetUint64(uint64(upperValue))
	}

	var isSinglePrefBlock bool
	result.maxValue = setMax(result.upperValue, bitCount)
	result.isPrefixBlock, isSinglePrefBlock, result.upperValueMasked =
		setCachedPrefixValues(result.value, result.upperValue, result.maxValue, prefLen, bitCount)

	if isSinglePrefBlock {
		result.cache.isSinglePrefBlock = &trueVal
	} else {
		result.cache.isSinglePrefBlock = &falseVal
	}

	return result
}

func setCachedPrefixValues(value, upperValue, maxValue *BigDivInt, prefLen PrefixLen, bitCount BitCount) (isPrefixBlock, isSinglePrefBlock bool, upperValueMasked *BigDivInt) {
	if prefLen != nil {
		if prefLen.Len() == bitCount {
			isPrefixBlock = true
			isSinglePrefBlock = value == upperValue
			upperValueMasked = upperValue
		} else if prefLen.Len() == 0 {
			valIsZero := bigIsZero(value)
			isFullRange := valIsZero && upperValue == maxValue
			isPrefixBlock = isFullRange
			isSinglePrefBlock = isFullRange
			if valIsZero {
				upperValueMasked = value
			} else {
				upperValueMasked = bigZeroConst()
			}
		} else {
			prefixLen := prefLen.Len()
			isPrefixBlock = testBigRange(value, upperValue, upperValue, bitCount, prefixLen)
			isSinglePrefBlock = testBigRange(value, value, upperValue, bitCount, prefixLen)
			upperValueMasked = setUpperValueMasked(value, upperValue, prefLen, bitCount)
		}
	} else {
		upperValueMasked = upperValue
	}
	return
}

func setUpperValueMasked(value, upperValue *BigDivInt, prefLen PrefixLen, bitCount BitCount) *BigDivInt {
	var networkMask big.Int
	networkMask.Lsh(bigMinusOneConst(), uint(bitCount-prefLen.Len())).And(upperValue, &networkMask)

	if networkMask.Cmp(upperValue) == 0 {
		return upperValue
	} else if networkMask.Cmp(value) == 0 {
		return value
	}

	return &networkMask
}

func testBigRangeMasks(lowerValue, upperValue, finalUpperValue, networkMask, hostMask *BigDivInt) bool {
	var one, two big.Int
	return lowerValue.CmpAbs(one.And(lowerValue, networkMask)) == 0 &&
		finalUpperValue.CmpAbs(two.Or(upperValue, hostMask)) == 0
}

func testBigRange(lowerValue, upperValue, finalUpperValue *BigDivInt, bitCount, divisionPrefixLen BitCount) bool {
	var networkMask, hostMask big.Int

	networkMask.Lsh(bigMinusOneConst(), uint(bitCount-divisionPrefixLen))
	hostMask.Not(&networkMask)

	return testBigRangeMasks(lowerValue, upperValue, finalUpperValue, &networkMask, &hostMask)
}

func setMax(assignedUpper *BigDivInt, bitCount BitCount) (max *BigDivInt) {
	var maxVal big.Int
	max = maxVal.Lsh(bigOneConst(), uint(bitCount)).Sub(&maxVal, bigOneConst())

	if max.CmpAbs(assignedUpper) == 0 {
		max = assignedUpper
	}

	return max
}

func setVal(valueBytes []byte, bitCount BitCount) (assignedValue *BigDivInt, assignedBitCount BitCount, maxVal *BigDivInt) {
	if bitCount < 0 {
		bitCount = 0
	}

	assignedBitCount = bitCount
	maxLen := (bitCount + 7) >> 3

	if len(valueBytes) >= maxLen {
		valueBytes = valueBytes[:maxLen]
	}

	assignedValue = new(big.Int).SetBytes(valueBytes)
	maxVal = setMax(assignedValue, bitCount)
	return
}

func setVals(valueBytes []byte, upperBytes []byte, bitCount BitCount) (assignedValue, assignedUpper *BigDivInt, assignedBitCount BitCount, maxVal *BigDivInt) {
	if bitCount < 0 {
		bitCount = 0
	}

	assignedBitCount = bitCount
	maxLen := (bitCount + 7) >> 3

	if len(valueBytes) >= maxLen || len(upperBytes) >= maxLen {
		extraBits := bitCount & 7
		mask := byte(0xff)
		if extraBits > 0 {
			mask = ^(mask << uint(8-extraBits))
		}
		if len(valueBytes) >= maxLen {
			valueBytes = valueBytes[len(valueBytes)-maxLen:]
			b := valueBytes[0]
			if b&mask != b {
				valueBytes = cloneBytes(valueBytes)
				valueBytes[0] &= mask
			}
		}
		if len(upperBytes) >= maxLen {
			upperBytes = upperBytes[len(upperBytes)-maxLen:]
			b := upperBytes[0]
			if b&mask != b {
				upperBytes = cloneBytes(upperBytes)
				upperBytes[0] &= mask
			}
		}
	}

	assignedValue = new(big.Int).SetBytes(valueBytes)

	if upperBytes == nil || bytes.Compare(valueBytes, upperBytes) == 0 {
		assignedUpper = assignedValue
	} else {
		assignedUpper = new(big.Int).SetBytes(upperBytes)
		cmp := assignedValue.CmpAbs(assignedUpper)
		if cmp == 0 {
			assignedUpper = assignedValue
		} else if cmp > 0 {
			// flip them
			assignedValue, assignedUpper = assignedUpper, assignedValue
		}
	}

	maxVal = setMax(assignedUpper, bitCount)
	return
}

func createLargeAddressDiv(vals divisionValues, defaultRadix int) *IPAddressLargeDivision {
	res := &IPAddressLargeDivision{
		addressLargeDivInternal{
			addressDivisionBase: addressDivisionBase{vals},
		},
	}

	if defaultRadix >= 2 {
		res.defaultRadix = new(big.Int).SetInt64(int64(defaultRadix))
	}

	return res
}

func newLargeDivValue(value []byte, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, bitCount, result.maxValue = setVal(value, bitCount)
	result.bitCount = bitCount
	result.upperValue = result.value
	result.upperValueMasked = result.upperValue
	result.cache.isSinglePrefBlock = &falseVal
	return result
}

func newLargeDivValues(value, upperValue []byte, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, result.upperValue, bitCount, result.maxValue = setVals(value, upperValue, bitCount)
	result.bitCount = bitCount
	result.isMult = result.value != result.upperValue
	result.upperValueMasked = result.upperValue
	result.cache.isSinglePrefBlock = &falseVal
	return result
}

// NewIPAddressLargeDivision creates a division of the given arbitrary bit-length, assigning it the given value.
// If the value's bit length exceeds the given bit length, it is truncated.
func NewIPAddressLargeDivision(val []byte, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivValue(val, bitCount), defaultRadix)
}

// NewIPAddressLargeRangeDivision creates a division of the given arbitrary bit-length, assigning it the given value range.
// If a value's bit length exceeds the given bit length, it is truncated.
func NewIPAddressLargeRangeDivision(val, upperVal []byte, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivValues(val, upperVal, bitCount), defaultRadix)
}
