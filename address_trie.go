package goip

import (
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/tree"
)

type trieBase[T TrieKeyConstraint[T], V any] struct {
	trie tree.BinTrie[trieKey[T], V]
}

// Trie is a compact binary trie (aka compact binary prefix tree, or binary radix trie), for addresses and/or CIDR prefix block subnets.
// The prefixes in used by the prefix trie are the CIDR prefixes, or the full address in the case of individual addresses with no prefix length.
// The elements of the trie are CIDR prefix blocks or addresses.
//
// For the generic type T, you can choose *Address, *IPAddress, *IPv4Address, *IPv6Address, or *MACAddress.
//
// The zero-value of an AddressTrie is a trie ready for use.  Its root will be nil until an element is added to it.
// Once any subnet or address is added to the trie, it will have an assigned root, and any further addition to the trie must match the type and version of the root,
// in addition to the generic type of the trie's keys.
// Once there is a root, the root cannot be removed.
//
// So, for instance, an instance of ipaddr.Trie[*ipaddr.IPAddress] can contain either IPv4 or IPv6 keys, but not both.
// Once it has been populated with the first key, all remaining additions must have the same IP version, even if the trie is cleared.
//
// Any trie can be copied. If a trie has no root, a copy produces a new zero-valued trie with no root.
// If a trie has a root, a copy produces a reference to the same trie, much like copying a map or slice.
//
// The trie data structure allows you to check an address for containment in many subnets at once, in constant time.
// The trie allows you to check a subnet for containment of many smaller subnets or addresses at once, in constant time.
// The trie allows you to check for equality of a subnet or address with a large number of subnets or addresses at once.
//
// There is only a single possible trie for any given set of address and subnets.  For one thing, this means they are automatically balanced.
// Also, this makes access to subtries and to the nodes themselves more useful, allowing for many of the same operations performed on the original trie.
//
// Each node has either a prefix block or a single address as its key.
// Each prefix block node can have two sub-nodes, each sub-node a prefix block or address contained by the node.
//
// There are more nodes in the trie than elements added to the trie.
// A node is considered "added" if it was explicitly added to the trie and is included as an element when viewed as a set.
// There are non-added prefix block nodes that are generated in the trie as well.
// When two or more added addresses share the same prefix up until they differ with the bit at index x,
// then a prefix block node is generated (if not already added to the trie) for the common prefix of length x,
// with the nodes for those addresses to be found following the lower
// or upper sub-nodes according to the bit at index x + 1 in each address.
// If that bit is 1, the node can be found by following the upper sub-node,
// and when it is 0, the lower sub-node.
//
// Nodes that were generated as part of the trie structure only
// because of other added elements are not elements of the represented set of addresses and subnets.
// The set elements are the elements that were explicitly added.
//
// You can work with parts of the trie, starting from any node in the trie,
// calling methods that start with any given node, such as iterating the subtrie,
// finding the first or last in the subtrie, doing containment checks with the subtrie, and so on.
//
// The binary trie structure defines a natural ordering of the trie elements.
// Addresses of equal prefix length are sorted by prefix value.  Addresses with no prefix length are sorted by address value.
// Addresses of differing prefix length are sorted according to the bit that follows the shorter prefix length in the address with the longer prefix length,
// whether that bit is 0 or 1 determines if that address is ordered before or after the address of shorter prefix length.
//
// The unique and pre-defined structure for a trie means that different means of traversing the trie can be more meaningful.
// This trie implementation provides 8 different ways of iterating through the trie:
//   - 1, 2: the natural sorted trie order, forward and reverse (spliterating is also an option for these two orders).  Use the methods NodeIterator, Iterator or DescendingIterator.  Functions for incrementing and decrementing keys, or comparing keys, is also provided for this order.
//   - 3, 4: pre-order tree traversal, in which parent node is visited before sub-nodes, with sub-nodes visited in forward or reverse order
//   - 5, 6: post-order tree traversal, in which sub-nodes are visited before parent nodes, with sub-nodes visited in forward or reverse order
//   - 7, 8: prefix-block order, in which larger prefix blocks are visited before smaller, and blocks of equal size are visited in forward or reverse sorted order
//
// All of these orderings are useful in specific contexts.
//
// If you create an iterator, then that iterator can no longer be advanced following any further modification to the trie.
// Any call to Next or Remove will panic if the trie was changed following creation of the iterator.
//
// You can do lookup and containment checks on all the subnets and addresses in the trie at once, in constant time.
// A generic trie data structure lookup is O(m) where m is the entry length.
// For this trie, which operates on address bits, entry length is capped at 128 bits for IPv6 and 32 bits for IPv4.
// That makes lookup a constant time operation.
// Subnet containment or equality checks are also constant time since they work the same way as lookup, by comparing prefix bits.
//
// For a generic trie data structure, construction is O(m * n) where m is entry length and n is the number of addresses,
// but for this trie, since entry length is capped at 128 bits for IPv6 and 32 bits for IPv4, construction is O(n),
// in linear proportion to the number of added elements.
//
// This trie also allows for constant time size queries (count of added elements, not node count), by storing sub-trie size in each node.
// It works by updating the size of every node in the path to any added or removed node.
// This does not change insertion or deletion operations from being constant time (because tree-depth is limited to address bit count).
// At the same this makes size queries constant time, rather than being O(n) time.
//
// A single trie can use just a single address type or version, since it works with bits alone,
// and cannot distinguish between different versions and types in the trie structure.
//
// Instead, you could aggregate multiple subtries to create a collection of multiple address types or versions.
// You can use the method ToString for a String that represents multiple tries as a single tree.
//
// Tries are concurrency-safe when not being modified (elements added or removed), but are not concurrency-safe when any goroutine is modifying the trie.
type Trie[T TrieKeyConstraint[T]] struct {
	trieBase[T, emptyValue]
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

func toAddressTrie[T TrieKeyConstraint[T]](trie *tree.BinTrie[trieKey[T], emptyValue]) *Trie[T] {
	return (*Trie[T])(unsafe.Pointer(trie))
}
