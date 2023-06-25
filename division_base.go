package goip

import "math/big"

type divCache struct {
	cachedString,
	cachedWildcardString,
	cached0xHexString,
	cachedHexString,
	cachedNormalizedString *string
	isSinglePrefBlock *bool
}

// divisionValuesBase provides an interface for divisions of any size.
// It is common for standard and large divisions.
// All methods can be called for any division.
type divisionValuesBase interface {
	getBitCount() BitCount
	getByteCount() int
	// getDivisionPrefixLength provides the prefix length,
	// if the alignment is true and the prefix is not nil,
	// all subsequent divisions in the same grouping have a zero length prefix
	getDivisionPrefixLength() PrefixLen
	// getValue gets the lower value as a BigDivInt
	getValue() *BigDivInt
	// getValue gets the upper value as a BigDivInt
	getUpperValue() *BigDivInt
	includesZero() bool
	includesMax() bool
	isMultiple() bool
	getCount() *big.Int
	// convert lower and upper values to byte arrays
	calcBytesInternal() (bytes, upperBytes []byte)
	bytesInternal(upper bool) (bytes []byte)
	// getCache returns a divCache for those divisions which cache their values, or nil otherwise
	getCache() *divCache
	getAddrType() addrType
}

// divisionValues provides methods to provide the values from divisions,
// and to create new divisions from values.
// Values may be truncated if the stored values in the interface implementation
// have larger bit-size than the return values.
// Similarly, values may be truncated if the supplied values have greater bit-size
// than the returned types.
type divisionValues interface {
	divisionValuesBase
	divIntVals
	divderiver
	segderiver
	segmentValues
}

// addressDivisionBase is a division of any bit size.
// It is common for standard and large division types.
// Large divisions should not use divisionValues methods and only use methods in divisionValuesBase.
type addressDivisionBase struct {
	divisionValues
}

func (div *addressDivisionBase) getDivisionPrefixLength() PrefixLen {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (div *addressDivisionBase) GetBitCount() BitCount {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getBitCount()
}

// GetByteCount returns the number of bytes needed for
// each value that makes up the given address element,
// rounded up if the number of bits is not a multiple of 8.
func (div *addressDivisionBase) GetByteCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getByteCount()
}

// GetValue returns the smallest value in the address division range as a large integer.
func (div *addressDivisionBase) GetValue() *BigDivInt {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getValue()
}

// GetUpperValue returns the highest value in the address division range as a big integer.
func (div *addressDivisionBase) GetUpperValue() *BigDivInt {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getUpperValue()
}

func (div *addressDivisionBase) getBytes() (bytes []byte) {
	return div.bytesInternal(false)
}

func (div *addressDivisionBase) getUpperBytes() (bytes []byte) {
	return div.bytesInternal(true)
}

// Bytes returns the lowest value in the address division range as a byte slice.
func (div *addressDivisionBase) Bytes() []byte {
	if div.divisionValues == nil {
		return emptyBytes
	}
	return div.getBytes()
}

// UpperBytes returns the highest value in the address division range as a byte slice.
func (div *addressDivisionBase) UpperBytes() []byte {
	if div.divisionValues == nil {
		return emptyBytes
	}
	return div.getUpperBytes()
}

func (div *addressDivisionBase) getCount() *big.Int {
	if !div.isMultiple() {
		return bigOne()
	}
	return div.divisionValues.getCount()
}

func (div *addressDivisionBase) isMultiple() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.isMultiple()
}

// GetPrefixCountLen returns a count of the number of distinct values in the prefix part of the address item, the bits that appear within the prefix length.
func (div *addressDivisionBase) GetPrefixCountLen(prefixLength BitCount) *big.Int {
	if prefixLength < 0 {
		return bigOne()
	}

	bitCount := div.GetBitCount()
	if prefixLength >= bitCount {
		return div.getCount()
	}

	ushiftAdjustment := uint(bitCount - prefixLength)
	lower := div.GetValue()
	upper := div.GetUpperValue()
	upper.Rsh(upper, ushiftAdjustment)
	lower.Rsh(lower, ushiftAdjustment)
	upper.Sub(upper, lower).Add(upper, bigOneConst())

	return upper
}
