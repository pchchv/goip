package goip

import "math/big"

type BigDivInt = big.Int

// IPAddressLargeDivision represents an arbitrary bit size division in an address or address division grouping.
// It can contain a single value or a range of consecutive values and has an assigned bit length.
// Like all address components, it is immutable.
type IPAddressLargeDivision struct {
	addressLargeDivInternal
}

type addressLargeDivInternal struct {
	addressDivisionBase
	defaultRadix *BigDivInt
}
