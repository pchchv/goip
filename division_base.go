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
	getAddrType() addressType
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
