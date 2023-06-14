package goip

import (
	"math/big"
	"unsafe"
)

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

func (div *largeDivValues) getAddrType() addressType {
	return zeroType
}

func (div *largeDivValues) includesZero() bool {
	return bigIsZero(div.value)
}

func (div *largeDivValues) getCount() *big.Int {
	var res big.Int
	return res.Sub(div.upperValue, div.value).Add(&res, bigOneConst())
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
