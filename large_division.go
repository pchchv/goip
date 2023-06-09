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

