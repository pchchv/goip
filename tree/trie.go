package tree

import "unsafe"

type EmptyValueType struct{}

// BinTrie is a binary trie.
//
// To use BinTrie, your keys implement TrieKey.
//
// All keys are either fixed, in which the key value does not change,
// or comprising of a prefix in which an initial sequence of bits does not change, and the the remaining bits represent all bit values.
// The length of the initial fixed sequence of bits is the prefix length.
// The total bit length is the same for all keys.
//
// A key with a prefix is also known as a prefix block, and represents all bit sequences with the same prefix.
//
// The zero value for BinTrie is a binary trie ready for use.
//
// Each node can be associated with a value, making BinTrie an associative binary trie.
// If you do not wish to associate values to nodes, then use the type EmptyValueType,
// in which case the value will be ignored in functions that print node strings.
type BinTrie[E TrieKey[E], V any] struct {
	binTree[E, V]
}

func (trie *BinTrie[E, V]) toBinTree() *binTree[E, V] {
	return (*binTree[E, V])(unsafe.Pointer(trie))
}

// GetRoot returns the root of this trie (in the case of bounded tries,
// this would be the bounded root)
func (trie *BinTrie[E, V]) GetRoot() (root *BinTrieNode[E, V]) {
	if trie != nil {
		root = toTrieNode(trie.root)
	}
	return
}

// Returns the root of this trie (in the case of bounded tries,
// the absolute root ignores the bounds)
func (trie *BinTrie[E, V]) absoluteRoot() (root *BinTrieNode[E, V]) {
	if trie != nil {
		root = toTrieNode(trie.root)
	}
	return
}

// Size returns the number of elements in the tree.
// Only nodes for which IsAdded() returns true are counted.
// When zero is returned, IsEmpty() returns true.
func (trie *BinTrie[E, V]) Size() int {
	return trie.toBinTree().Size()
}

// NodeSize returns the number of nodes in the tree,
// which is always more than the number of elements.
func (trie *BinTrie[E, V]) NodeSize() int {
	return trie.toBinTree().NodeSize()
}
