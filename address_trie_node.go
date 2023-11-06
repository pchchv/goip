package goip

import (
	"fmt"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/tree"
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

type trieKey[T TrieKeyConstraint[T]] struct {
	address T
}

// ToPrefixBlockLen returns the address key associated with the prefix length provided,
// the address key whose prefix of that length matches the prefix of this address key, and the remaining bits span all values.
//
// The returned address key will represent all addresses with the same prefix as this one, the prefix "block".
func (a trieKey[T]) ToPrefixBlockLen(bitCount BitCount) trieKey[T] {
	addr := a.address.ToPrefixBlockLen(bitCount)
	addr.toAddressBase().assignTrieCache()
	return trieKey[T]{address: addr}
}

func (a trieKey[T]) GetBitCount() tree.BitCount {
	return a.address.GetBitCount()
}

func (a trieKey[T]) String() string {
	return a.address.String()
}

func (a trieKey[T]) IsOneBit(bitIndex tree.BitCount) bool {
	return a.address.IsOneBit(bitIndex)
}

func (a trieKey[T]) GetTrailingBitCount(ones bool) tree.BitCount {
	return a.address.getTrailingBitCount(ones)
}
