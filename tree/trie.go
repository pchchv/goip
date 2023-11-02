package tree

import (
	"fmt"
	"unsafe"
)

type EmptyValueType struct{}

type AddedSubnodeMapping any // AddedSubnodeMapping / any is always SubNodesMapping[E,V]

type SubNodesMapping[E TrieKey[E], V any] struct {
	Value    V
	SubNodes []*BinTrieNode[E, AddedSubnodeMapping] // subNodes is the list of direct and indirect added subnodes in the original trie
}

type printWrapper[E TrieKey[E], V any] struct {
	*BinTrieNode[E, AddedSubnodeMapping]
}

func (p printWrapper[E, V]) GetValue() V {
	var nodeValue AddedSubnodeMapping = p.BinTrieNode.GetValue()
	if nodeValue == nil {
		var v V
		return v
	}
	return nodeValue.(SubNodesMapping[E, V]).Value
}

type indentsNode[E TrieKey[E]] struct {
	inds indents
	node *BinTrieNode[E, AddedSubnodeMapping]
}

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

// String returns a visual representation of the tree with one node per line.
func (trie *BinTrie[E, V]) String() string {
	if trie == nil {
		return nilString()
	}
	return trie.binTree.String()
}

// TreeString returns a visual representation of the tree with one node per line,
// with or without the non-added keys.
func (trie *BinTrie[E, V]) TreeString(withNonAddedKeys bool) string {
	if trie == nil {
		return "\n" + nilString()
	}
	return trie.binTree.TreeString(withNonAddedKeys)
}

// For some reason Format must be here and not in addressTrieNode for nil node.
// It panics in fmt code either way,
// but if in here then it is handled by a recover() call in fmt properly.
// Seems to be a problem only in the debugger.
//
// Format implements the fmt.Formatter interface
func (trie BinTrie[E, V]) Format(state fmt.State, verb rune) {
	trie.format(state, verb)
}

func (trie *BinTrie[E, V]) FirstNode() *BinTrieNode[E, V] {
	return trie.absoluteRoot().FirstNode()
}

func (trie *BinTrie[E, V]) FirstAddedNode() *BinTrieNode[E, V] {
	return trie.absoluteRoot().FirstAddedNode()
}

func (trie *BinTrie[E, V]) LastNode() *BinTrieNode[E, V] {
	return trie.absoluteRoot().LastNode()
}

func (trie *BinTrie[E, V]) LastAddedNode() *BinTrieNode[E, V] {
	return trie.absoluteRoot().LastAddedNode()
}

func TreesString[E TrieKey[E], V any](withNonAddedKeys bool, tries ...*BinTrie[E, V]) string {
	binTrees := make([]*binTree[E, V], 0, len(tries))
	for _, trie := range tries {
		binTrees = append(binTrees, tobinTree(trie))
	}
	return treesString(withNonAddedKeys, binTrees...)
}

func tobinTree[E TrieKey[E], V any](trie *BinTrie[E, V]) *binTree[E, V] {
	return (*binTree[E, V])(unsafe.Pointer(trie))
}
