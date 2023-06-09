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

// IsMultiple returns true if the given division represents a consecutive range of values or a single value.
func (div *IPAddressLargeDivision) IsMultiple() bool {
	return div != nil && div.isMultiple()
}

// IsPrefixed returns whether the given division has a prefix length associated with it.
// If so, the prefix length is given by GetDivisionPrefixLen()
func (div *IPAddressLargeDivision) IsPrefixed() bool {
	return div.GetDivisionPrefixLen() != nil
}
