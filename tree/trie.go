package tree

import (
	"fmt"
	"strings"
	"sync"
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

func (trie *BinTrie[E, V]) Clone() *BinTrie[E, V] {
	if trie == nil {
		return nil
	}
	return &BinTrie[E, V]{binTree[E, V]{root: trie.absoluteRoot().CloneTree().toBinTreeNode()}}
}

// DeepEqual returns whether the given argument is a trie with
// a set of nodes with the same keys as in this trie according to the Compare method,
// and the same values according to the reflect.DeepEqual method
func (trie *BinTrie[E, V]) DeepEqual(other *BinTrie[E, V]) bool {
	return trie.absoluteRoot().TreeDeepEqual(other.absoluteRoot())
}

// Equal returns whether the given argument is a trie with
// a set of nodes with the same keys as in this trie according to the Compare method
func (trie *BinTrie[E, V]) Equal(other *BinTrie[E, V]) bool {
	return trie.absoluteRoot().TreeEqual(other.absoluteRoot())
}

func (trie *BinTrie[E, V]) ensureRoot(key E) *BinTrieNode[E, V] {
	root := trie.root
	if root == nil {
		root = trie.setRoot(key.ToPrefixBlockLen(0))
	}
	return toTrieNode(root)
}

func (trie *BinTrie[E, V]) setRoot(key E) *binTreeNode[E, V] {
	root := &binTreeNode[E, V]{
		item:     key,
		cTracker: &changeTracker{},
		pool: &sync.Pool{
			New: func() any { return &opResult[E, V]{} },
		},
	}
	root.setAddr()
	trie.root = root
	return root
}

// Iterator returns an iterator that iterates through the elements of the sub-tree with this node as the root.
// The iteration is in sorted element order.
func (trie *BinTrie[E, V]) Iterator() TrieKeyIterator[E] {
	return trie.GetRoot().Iterator()
}

// DescendingIterator returns an iterator that iterates through the elements of the subtrie with this node as the root.
// The iteration is in reverse sorted element order.
func (trie *BinTrie[E, V]) DescendingIterator() TrieKeyIterator[E] {
	return trie.GetRoot().DescendingIterator()
}

// Add adds the given key to the trie, returning true if not there already.
func (trie *BinTrie[E, V]) Add(key E) bool {
	root := trie.ensureRoot(key)
	result := &opResult[E, V]{
		key: key,
		op:  insert,
	}
	root.matchBits(result)
	return !result.exists
}

func (trie *BinTrie[E, V]) Contains(key E) bool {
	return trie.absoluteRoot().Contains(key)
}

func (trie *BinTrie[E, V]) Remove(key E) bool {
	return trie.absoluteRoot().RemoveNode(key)
}

func (trie *BinTrie[E, V]) RemoveElementsContainedBy(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().RemoveElementsContainedBy(key)
}

func (trie *BinTrie[E, V]) ElementContains(key E) bool {
	return trie.absoluteRoot().ElementContains(key)
}

func (trie *BinTrie[E, V]) ElementsContainedBy(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().ElementsContainedBy(key)
}

func (trie *BinTrie[E, V]) ElementsContaining(key E) *Path[E, V] {
	return trie.absoluteRoot().ElementsContaining(key)
}

// LongestPrefixMatch finds the added key with the longest matching prefix.
func (trie *BinTrie[E, V]) LongestPrefixMatch(key E) (E, bool) {
	return trie.absoluteRoot().LongestPrefixMatch(key)
}

// LongestPrefixMatchNode finds the added node with the longest matching prefix.
func (trie *BinTrie[E, V]) LongestPrefixMatchNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().LongestPrefixMatchNode(key)
}

// ShortestPrefixMatch finds the added key with the shortest matching prefix.
func (trie *BinTrie[E, V]) ShortestPrefixMatch(key E) (E, bool) {
	return trie.absoluteRoot().ShortestPrefixMatch(key)
}

// ShortestPrefixMatchNode finds the added node whose key has the shortest matching prefix.
func (trie *BinTrie[E, V]) ShortestPrefixMatchNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().ShortestPrefixMatchNode(key)
}

// GetNode gets the node in the sub-trie corresponding to the given address,
// or returns nil if not such element exists.
//
// It returns any node, whether added or not,
// including any prefix block node that was not added.
func (trie *BinTrie[E, V]) GetNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().GetNode(key)
}

// GetAddedNode gets trie nodes representing added elements.
//
// Use Contains to check for the existence of a given address in the trie,
// as well as GetNode to search for all nodes including those not-added
// but also auto-generated nodes for subnet blocks.
func (trie *BinTrie[E, V]) GetAddedNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().GetAddedNode(key)
}

// Put associates the specified value with the specified key in this map.
//
// If the argument is not a single address nor prefix block, this method will panic.
// The Partition type can be used to convert the argument to
// single addresses and prefix blocks before calling this method.
//
// If this map previously contained a mapping for a key,
// the old value is replaced by the specified value,
// and false is returned along with the old value,
// which may be the zero value.
// If this map did not previously contain a mapping for the key,
// true is returned along with the zero value.
func (trie *BinTrie[E, V]) Put(key E, value V) (V, bool) {
	root := trie.ensureRoot(key)
	result := &opResult[E, V]{
		key:      key,
		op:       insert,
		newValue: value,
		// new value assignment
	}
	root.matchBits(result)
	return result.existingValue, !result.exists
}

func (trie *BinTrie[E, V]) PutNode(key E, value V) *BinTrieNode[E, V] {
	root := trie.ensureRoot(key)
	result := &opResult[E, V]{
		key:      key,
		op:       insert,
		newValue: value,
		// new value assignment
	}
	root.matchBits(result)
	resultNode := result.existingNode
	if resultNode == nil {
		resultNode = result.inserted
	}
	return resultNode
}

func (trie *BinTrie[E, V]) remapImpl(key E, remapper func(val V, exists bool) (V, remapAction)) *BinTrieNode[E, V] {
	root := trie.ensureRoot(key)
	result := &opResult[E, V]{
		key:      key,
		op:       remap,
		remapper: remapper,
	}
	root.matchBits(result)
	resultNode := result.existingNode
	if resultNode == nil {
		resultNode = result.inserted
	}
	return resultNode
}

func (trie *BinTrie[E, V]) Remap(key E, remapper func(existing V, found bool) (mapped V, mapIt bool)) *BinTrieNode[E, V] {
	return trie.remapImpl(key,
		func(existingVal V, exists bool) (V, remapAction) {
			result, mapIt := remapper(existingVal, exists)
			if mapIt {
				return result, remapValue
			}
			var v V
			return v, removeNode
		})
}

func (trie *BinTrie[E, V]) RemapIfAbsent(key E, supplier func() V) *BinTrieNode[E, V] {
	return trie.remapImpl(key,
		func(existingVal V, exists bool) (V, remapAction) {
			if !exists {
				return supplier(), remapValue
			}
			var v V
			return v, doNothing
		})
}

func (trie *BinTrie[E, V]) Get(key E) (V, bool) {
	return trie.absoluteRoot().Get(key)
}

func (trie *BinTrie[E, V]) LowerAddedNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().LowerAddedNode(key)
}

func (trie *BinTrie[E, V]) HigherAddedNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().HigherAddedNode(key)
}

func (trie *BinTrie[E, V]) FloorAddedNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().FloorAddedNode(key)
}

func (trie *BinTrie[E, V]) CeilingAddedNode(key E) *BinTrieNode[E, V] {
	return trie.absoluteRoot().CeilingAddedNode(key)
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
