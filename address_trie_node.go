package goip

import (
	"fmt"

	"github.com/pchchv/goip/address_error"
)

// TrieKeyConstraint is the generic type constraint used for tree keys,
// which are individual addresses and prefix block subnets.
type TrieKeyConstraint[T any] interface {
	comparable
	BitItem
	fmt.Stringer
	PrefixedConstraint[T]
	IsOneBit(index BitCount) bool // AddressComponent
	toAddressBase() *Address      // AddressType - used by MatchBits
	getPrefixLen() PrefixLen
	toMaxLower() T
	toMinUpper() T
	trieCompare(other *Address) int
	getTrailingBitCount(ones bool) BitCount
	toSinglePrefixBlockOrAddress() (T, address_error.IncompatibleAddressError)
}
