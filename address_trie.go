package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/tree"
)

type trieBase[T TrieKeyConstraint[T], V any] struct {
	trie tree.BinTrie[trieKey[T], V]
}

// Ensures the address is either an individual address or a prefix block subnet.
// Returns a normalized address which has no prefix length if it is a single address,
// or has a prefix length matching the prefix block size if it is a prefix block.
func checkBlockOrAddress[T TrieKeyConstraint[T]](addr T) (res T, err address_error.IncompatibleAddressError) {
	return addr.toSinglePrefixBlockOrAddress()
}

// Ensures the address is either an individual address or a prefix block subnet.
func mustBeBlockOrAddress[T TrieKeyConstraint[T]](addr T) T {
	res, err := checkBlockOrAddress(addr)
	if err != nil {
		panic(err)
	}
	return res
}
