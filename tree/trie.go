package tree

import (
	"fmt"
	"strings"
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

// NodeIterator returns an iterator that iterates through the added nodes of
// the trie in forward or reverse tree order.
func (trie *BinTrie[E, V]) NodeIterator(forward bool) TrieNodeIteratorRem[E, V] {
	return trie.absoluteRoot().NodeIterator(forward)
}

// AllNodeIterator returns an iterator that iterates through all
// the nodes of the trie in forward or reverse tree order.
func (trie *BinTrie[E, V]) AllNodeIterator(forward bool) TrieNodeIteratorRem[E, V] {
	return trie.absoluteRoot().AllNodeIterator(forward)
}

// BlockSizeNodeIterator returns an iterator that iterates the added nodes in the trie,
// ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first, otherwise the reverse order
func (trie *BinTrie[E, V]) BlockSizeNodeIterator(lowerSubNodeFirst bool) TrieNodeIteratorRem[E, V] {
	return trie.absoluteRoot().BlockSizeNodeIterator(lowerSubNodeFirst)
}

// BlockSizeAllNodeIterator returns an iterator that iterates all nodes in the trie,
// ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first, otherwise the reverse order
func (trie *BinTrie[E, V]) BlockSizeAllNodeIterator(lowerSubNodeFirst bool) TrieNodeIteratorRem[E, V] {
	return trie.absoluteRoot().BlockSizeAllNodeIterator(lowerSubNodeFirst)
}

// BlockSizeCachingAllNodeIterator returns an iterator that iterates all nodes,
// ordered by keys from largest prefix blocks to smallest, and then to individual addresses.
func (trie *BinTrie[E, V]) BlockSizeCachingAllNodeIterator() CachingTrieNodeIterator[E, V] {
	return trie.absoluteRoot().BlockSizeCachingAllNodeIterator()
}

func (trie *BinTrie[E, V]) ContainingFirstIterator(forwardSubNodeOrder bool) CachingTrieNodeIterator[E, V] {
	return trie.absoluteRoot().ContainingFirstIterator(forwardSubNodeOrder)
}

func (trie *BinTrie[E, V]) ContainingFirstAllNodeIterator(forwardSubNodeOrder bool) CachingTrieNodeIterator[E, V] {
	return trie.absoluteRoot().ContainingFirstAllNodeIterator(forwardSubNodeOrder)
}

func (trie *BinTrie[E, V]) ContainedFirstIterator(forwardSubNodeOrder bool) TrieNodeIteratorRem[E, V] {
	return trie.absoluteRoot().ContainedFirstIterator(forwardSubNodeOrder)
}

func (trie *BinTrie[E, V]) ContainedFirstAllNodeIterator(forwardSubNodeOrder bool) TrieNodeIterator[E, V] {
	return trie.absoluteRoot().ContainedFirstAllNodeIterator(forwardSubNodeOrder)
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

// AddedNodesTreeString provides a flattened version of
// the trie showing only the contained added nodes and their containment structure,
// which is non-binary.
// The root node is included, which may or may not be added.
func AddedNodesTreeString[E TrieKey[E], V any](addedTree *BinTrieNode[E, AddedSubnodeMapping]) string {
	var stack []indentsNode[E]
	builder := strings.Builder{}
	builder.WriteByte('\n')
	nodeIndent, subNodeIndent := "", ""
	nextNode := addedTree
	for {
		builder.WriteString(nodeIndent)
		builder.WriteString(NodeString[E, V](printWrapper[E, V]{nextNode}))
		builder.WriteByte('\n')

		var nextVal AddedSubnodeMapping // SubNodesMapping[E, V]
		nextVal = nextNode.GetValue()
		var nextNodes []*BinTrieNode[E, AddedSubnodeMapping]
		if nextVal != nil {
			mapping := nextVal.(SubNodesMapping[E, V])
			if mapping.SubNodes != nil {
				nextNodes = mapping.SubNodes
			}
		}
		if len(nextNodes) > 0 {
			i := len(nextNodes) - 1
			lastIndents := indents{
				nodeIndent: subNodeIndent + rightElbow,
				subNodeInd: subNodeIndent + belowElbows,
			}

			var nNode *BinTrieNode[E, AddedSubnodeMapping] // SubNodesMapping[E, V]
			nNode = nextNodes[i]
			if stack == nil {
				stack = make([]indentsNode[E], 0, addedTree.Size())
			}
			stack = append(stack, indentsNode[E]{lastIndents, nNode})
			if len(nextNodes) > 1 {
				firstIndents := indents{
					nodeIndent: subNodeIndent + leftElbow,
					subNodeInd: subNodeIndent + inBetweenElbows,
				}
				for i--; i >= 0; i-- {
					nNode = nextNodes[i]
					stack = append(stack, indentsNode[E]{firstIndents, nNode})
				}
			}
		}
		stackLen := len(stack)
		if stackLen == 0 {
			break
		}
		newLen := stackLen - 1
		nextItem := stack[newLen]
		stack = stack[:newLen]
		nextNode = nextItem.node
		nextIndents := nextItem.inds
		nodeIndent = nextIndents.nodeIndent
		subNodeIndent = nextIndents.subNodeInd
	}
	return builder.String()
}
