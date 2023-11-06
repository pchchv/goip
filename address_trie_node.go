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

func (a trieKey[T]) GetPrefixLen() tree.PrefixLen {
	return tree.PrefixLen(a.address.getPrefixLen())
}

// Compare compares to provide the same ordering used by the trie,
// an ordering that works with prefix block subnets and individual addresses.
// The comparator is consistent with the equality of address instances
// and can be used in other contexts.  However, it only works with prefix blocks and individual addresses,
// not with addresses like 1-2.3.4.5-6 which cannot be differentiated using this comparator from 1.3.4.5
// and is thus not consistent with equality for subnets that are not CIDR prefix blocks.
//
// The comparator first compares the prefix of addresses, with the full address value considered the prefix when
// there is no prefix length, ie when it is a single address.  It takes the minimum m of the two prefix lengths and
// compares those m prefix bits in both addresses.  The ordering is determined by which of those two values is smaller or larger.
//
// If both prefix lengths match then both addresses are equal.
// Otherwise it looks at bit m in the address with larger prefix.  If 1 it is larger and if 0 it is smaller than the other.
//
// When comparing an address with a prefix p and an address without, the first p bits in both are compared, and if equal,
// the bit at index p in the non-prefixed address determines the ordering, if 1 it is larger and if 0 it is smaller than the other.
//
// When comparing an address with prefix length matching the bit count to an address with no prefix, they are considered equal if the bits match.
// For instance, 1.2.3.4/32 is equal to 1.2.3.4, and thus the trie does not allow 1.2.3.4/32 in the trie since it is indistinguishable from 1.2.3.4,
// instead 1.2.3.4/32 is converted to 1.2.3.4 when inserted into the trie.
//
// When comparing 0.0.0.0/0, which has no prefix, to other addresses, the first bit in the other address determines the ordering.
// If 1 it is larger and if 0 it is smaller than 0.0.0.0/0.
func (a trieKey[T]) Compare(other trieKey[T]) int {
	return a.address.trieCompare(other.address.toAddressBase())
}

func (a trieKey[T]) GetTrieKeyData() *tree.TrieKeyData {
	return a.address.toAddressBase().getTrieCache()
}

// ToMaxLower changes this key to a new key with a 0 at the first bit beyond the prefix,
// followed by all ones, and with no prefix length.
func (a trieKey[T]) ToMaxLower() trieKey[T] {
	return createKey(a.address.toMaxLower())
}

// ToMinUpper changes this key to a new key with a 1 at the first bit beyond the prefix,
// followed by all zeros, and with no prefix length.
func (a trieKey[T]) ToMinUpper() trieKey[T] {
	return createKey(a.address.toMinUpper())
}

func createKey[T TrieKeyConstraint[T]](addr T) trieKey[T] {
	return trieKey[T]{address: addr}
}
