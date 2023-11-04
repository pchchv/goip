package tree

import (
	"fmt"
	"reflect"
	"sync"
	"unsafe"
)

const (
	doNothing remapAction = iota
	removeNode
	remapValue

	// Given a key E
	near           operation = iota // closest match, going down trie to get element considered closest. Whether one thing is closer than another is determined by the sorted order.
	remap                           // alters nodes based on the existing nodes and their values
	insert                          // add node for E if not already there
	lookup                          // find node for E, traversing all containing elements along the way
	containing                      // find a single node whose keys contain E
	allContaining                   // list the nodes whose keys contain E
	insertedDelete                  // Remove node for E
)

type TrieKeyData struct {
	Is32Bits  bool
	Is128Bits bool
	PrefLen   PrefixLen
	// 32-bit fields
	Uint32Val        uint32
	Mask32Val        uint32
	NextBitMask32Val uint32
	// 128-bit fields
	Uint64HighVal    uint64
	Uint64LowVal     uint64
	Mask64HighVal    uint64
	Mask64LowVal     uint64
	NextBitMask64Val uint64
}

type operation int

// KeyCompareResult has callbacks for a key comparison of a new key with a key pre-existing in the trie.
// At most one of the two methods should be called when comparing keys.
// If existing key is shorter, and the new key matches all bits in the existing key, then neither method should be called.
type KeyCompareResult interface {
	// BitsMatch should be called when the existing key is the same size or large as the new key and the new key bits match the existing key bits.
	BitsMatch()
	// BitsMatchPartially should be called when the existing key is shorter than the new key and the existing key bits match the new key bits.
	// It returns true if further matching is required, which might eventually result in calls to BitsMatch or BitsDoNotMatch.
	BitsMatchPartially() bool
	// BitsDoNotMatch should be called when at least one bit in the new key does not match the same bit in the existing key.
	// You can skip calling it if a prior call to MismatchCallbackRequired returns true.
	BitsDoNotMatch(matchedBits BitCount)
	// MismatchCallbackRequired indicates if you need to call BitsDoNotMatch for a mismatch
	MismatchCallbackRequired() bool
}

// TrieKey represents a key for a trie.
//
// All trie keys represent a sequence of bits.
// The bit count, which is the same for all keys,
// is the total number of bits in the key.
//
// Some trie keys represent a fixed sequence of bits.
// The bits have a single value.
//
// The remaining trie keys have an initial sequence of bits, the prefix, within which the bits are fixed,
// and the remaining bits beyond the prefix are not fixed and represent all potential bit values.
// Such keys represent all values with the same prefix.
//
// When all bits in a given key are fixed, the key has no prefix or prefix length.
//
// When not all bits are fixed, the prefix length is the number of bits in the initial fixed sequence.
// A key with a prefix length is also known as a prefix block.
//
// A key should never change.
// For keys with a prefix length,
// the prefix length must remain constance,
// and the prefix bits must remain constant.
// For keys with no prefix length,
// all the key bits must remain constant.
type TrieKey[E any] interface {
	comparable
	// MatchBits matches the bits in this key to the bits in the given key, starting from the given bit index.
	// Only the remaining bits in the prefix can be compared for either key.
	// If the prefix length of a key is nil, all the remaining bits can be compared.
	//
	// MatchBits returns false on a successful match or mismatch,
	// and true if only a partial match, in which case further trie traversal is required.
	// In the case where continueToNext is true,
	// followingBitsFlag is 0 if the single bit in the given key that follows the prefix length of this key is zero, and non-zero otherwise.
	//
	// MatchBits calls BitsMatch in handleMatch when the given key matches all the bits in this key (even if this key has a shorter prefix),
	// or calls BitsDoNotMatch in handleMatch when there is a mismatch of bits, returning true in both cases.
	//
	// If the given key has a shorter prefix length, so not all bits in this key can be compared to the given key,
	// but the bits that can be compared are a match, then that is a partial match.
	// MatchBits calls neither method in handleMatch and returns false in that case.
	MatchBits(key E, bitIndex BitCount, simpleMatch bool, handleMatch KeyCompareResult, trieKeyData *TrieKeyData) (continueToNext bool, followingBitsFlag uint64)
	// Compare returns a negative integer, zero, or a positive integer if this instance is less than, equal, or greater than the give item.
	// When comparing, the first mismatched bit determines the result.
	// If either key is prefixed, you compare only the bits up until the minumum prefix length.
	// If those bits are equal, and both have the same prefix length, they are equal.
	// Otherwise, the next bit in the key with the longer prefix (or no prefix at all) determines the result.
	// If that bit is 1, that key is larger, if it is 0, then smaller.
	Compare(E) int
	// GetBitCount returns the bit count for the key, which is a fixed value for any and all keys in the trie.
	GetBitCount() BitCount
	// GetPrefixLen returns the prefix length if this key has a prefix length (ie it is a prefix block).
	// It returns nil if not a prefix block.
	GetPrefixLen() PrefixLen
	// IsOneBit returns whether a given bit in the prefix is 1.
	// If the key is a prefix block, the operation is undefined if the bit index falls outside the prefix.
	// This method will never be called with a bit index that exceeds the prefix.
	IsOneBit(bitIndex BitCount) bool
	// ToPrefixBlockLen creates a new key with a prefix of the given length
	ToPrefixBlockLen(prefixLen BitCount) E
	// GetTrailingBitCount returns the number of trailing ones or zeros in the key.
	// If the key has a prefix length, GetTrailingBitCount is undefined.
	// This method will never be called on a key with a prefix length.
	GetTrailingBitCount(ones bool) BitCount
	// ToMaxLower returns a new key. If this key has a prefix length,
	// it is converted to a key with a 0 as the first bit following the prefix,
	// followed by all ones to the end, and with the prefix length then removed.
	// It returns this same key if it has no prefix length.
	// For instance, if this key is 1010**** with a prefix length of 4,
	// the returned key is 10100111 with no prefix length.
	ToMaxLower() E
	// ToMinUpper returns a new key. If this key has a prefix length,
	// it is converted to a key with a 1 as the first bit following the prefix,
	// followed by all zeros to the end, and with the prefix length then removed.
	// It returns this same key if it has no prefix length.
	// For instance, if this key is 1010**** with a prefix length of 4, the returned key is 10101000 with no prefix length.
	ToMinUpper() E
	// GetTrieKeyData provides a condensed set of mask, prefix length, and values
	// from 32-bit and 128-bit keys for optimized search.
	// Implementing this method is optional, even for 32-bit and 128-bit keys, it can return nil.
	GetTrieKeyData() *TrieKeyData
}

type remapAction int

type BinTrieNode[E TrieKey[E], V any] struct {
	binTreeNode[E, V]
}

// toBinTreeNode works with nil.
func (node *BinTrieNode[E, V]) toBinTreeNode() *binTreeNode[E, V] {
	return (*binTreeNode[E, V])(unsafe.Pointer(node))
}

// setKey sets the key used for placing the node in the tree.
// when freezeRoot is true, this is never called (and freezeRoot is always true)
func (node *BinTrieNode[E, V]) setKey(item E) {
	node.binTreeNode.setKey(item)
}

// GetKey gets the key used for placing the node in the tree.
func (node *BinTrieNode[E, V]) GetKey() E {
	return node.toBinTreeNode().GetKey()
}

// IsRoot returns whether this is the root of the backing tree.
func (node *BinTrieNode[E, V]) IsRoot() bool {
	return node.toBinTreeNode().IsRoot()
}

// IsAdded returns whether the node was "added".
// Some binary tree nodes are considered "added" and others are not.
// Those nodes created for key elements added to the tree are "added" nodes.
// Those that are not added are those nodes created to serve as junctions for the added nodes.
// Only added elements contribute to the size of a tree.
// When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
// which is when an added node has less than two added sub-nodes.
func (node *BinTrieNode[E, V]) IsAdded() bool {
	return node.toBinTreeNode().IsAdded()
}

// Clear removes this node and all sub-nodes from the tree, after which isEmpty() will return true.
func (node *BinTrieNode[E, V]) Clear() {
	node.toBinTreeNode().Clear()
}

// IsEmpty returns where there are not any elements in the sub-tree with this node as the root.
func (node *BinTrieNode[E, V]) IsEmpty() bool {
	return node.toBinTreeNode().IsEmpty()
}

// IsLeaf returns whether this node is in the tree (a node for which IsAdded() is true)
// and there are no elements in the sub-tree with this node as the root.
func (node *BinTrieNode[E, V]) IsLeaf() bool {
	return node.toBinTreeNode().IsLeaf()
}

func (node *BinTrieNode[E, V]) GetValue() (val V) {
	return node.toBinTreeNode().GetValue()
}

func (node *BinTrieNode[E, V]) ClearValue() {
	node.toBinTreeNode().ClearValue()
}

// Remove removes this node from the collection of added nodes,
// and also removes from the tree if possible.
// If it has two sub-nodes, it cannot be removed from the tree,
// in which case it is marked as not "added",
// nor is it counted in the tree size.
// Only added nodes can be removed from the tree.
// If this node is not added, this method does nothing.
func (node *BinTrieNode[E, V]) Remove() {
	node.toBinTreeNode().Remove()
}

// NodeSize returns the count of all nodes in
// the tree starting from this node and extending to all sub-nodes.
// Unlike for the Size method, this is not
// a constant-time operation and must visit all sub-nodes of this node.
func (node *BinTrieNode[E, V]) NodeSize() int {
	return node.toBinTreeNode().NodeSize()
}

// Size returns the count of nodes added to
// the sub-tree starting from this node as root
// and moving downwards to sub-nodes.
// This is a constant-time operation since
// the size is maintained in each node and adjusted with each add
// and Remove operation in the sub-tree.
func (node *BinTrieNode[E, V]) Size() int {
	return node.toBinTreeNode().Size()
}

// TreeString returns a visual representation of the sub-tree with this node as root,
// with one node per line.
//
// withNonAddedKeys: whether to show nodes that are not added nodes
// withSizes: whether to include the counts of added nodes in each sub-tree
func (node *BinTrieNode[E, V]) TreeString(withNonAddedKeys, withSizes bool) string {
	return node.toBinTreeNode().TreeString(withNonAddedKeys, withSizes)
}

// Returns a visual representation of this node including the key,
// with an open circle indicating this node is not an added node,
// a closed circle indicating this node is an added node.
func (node *BinTrieNode[E, V]) String() string {
	return node.toBinTreeNode().String()
}

func (node *BinTrieNode[E, V]) setUpper(upper *BinTrieNode[E, V]) {
	node.binTreeNode.setUpper(&upper.binTreeNode)
}

func (node *BinTrieNode[E, V]) setLower(lower *BinTrieNode[E, V]) {
	node.binTreeNode.setLower(&lower.binTreeNode)
}

// GetUpperSubNode gets the direct child node whose key is largest in value.
func (node *BinTrieNode[E, V]) GetUpperSubNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().getUpperSubNode())
}

// GetLowerSubNode gets the direct child node whose key is smallest in value.
func (node *BinTrieNode[E, V]) GetLowerSubNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().getLowerSubNode())
}

// GetParent gets the node from which this node is a direct child node,
// or nil if this is the root.
func (node *BinTrieNode[E, V]) GetParent() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().getParent())
}

func (node *BinTrieNode[E, V]) createNew(newKey E) *BinTrieNode[E, V] {
	res := &BinTrieNode[E, V]{
		binTreeNode: binTreeNode[E, V]{
			item:     newKey,
			cTracker: node.cTracker,
			pool:     node.pool,
		},
	}
	res.setAddr()
	return res
}

// The current node is replaced by a new block of the given key.
// The current node and given node become sub-nodes.
func (node *BinTrieNode[E, V]) replaceToSub(newAssignedKey E, totalMatchingBits BitCount, newSubNode *BinTrieNode[E, V]) *BinTrieNode[E, V] {
	newNode := node.createNew(newAssignedKey)
	newNode.storedSize = node.storedSize
	parent := node.GetParent()
	if parent.GetUpperSubNode() == node {
		parent.setUpper(newNode)
	} else if parent.GetLowerSubNode() == node {
		parent.setLower(newNode)
	}

	existingKey := node.GetKey()
	if totalMatchingBits < existingKey.GetBitCount() &&
		existingKey.IsOneBit(totalMatchingBits) {
		if newSubNode != nil {
			newNode.setLower(newSubNode)
		}
		newNode.setUpper(node)
	} else {
		newNode.setLower(node)
		if newSubNode != nil {
			newNode.setUpper(newSubNode)
		}
	}
	return newNode
}

// PreviousAddedNode returns the previous node in the tree that is an added node,
// following the tree order in reverse,
// or nil if there is no such node.
func (node *BinTrieNode[E, V]) PreviousAddedNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().previousAddedNode())
}

// NextAddedNode returns the next node in the tree that is an added node,
// following the tree order,
// or nil if there is no such node.
func (node *BinTrieNode[E, V]) NextAddedNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().nextAddedNode())
}

// NextNode returns the node that follows this node following the tree order
func (node *BinTrieNode[E, V]) NextNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().nextNode())
}

// PreviousNode returns the node that precedes this node following the tree order.
func (node *BinTrieNode[E, V]) PreviousNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().previousNode())
}

func (node *BinTrieNode[E, V]) FirstNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().firstNode())
}

func (node *BinTrieNode[E, V]) FirstAddedNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().firstAddedNode())
}

func (node *BinTrieNode[E, V]) LastNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().lastNode())
}

func (node *BinTrieNode[E, V]) LastAddedNode() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().lastAddedNode())
}

// Clone clones the node.
// Keys remain the same, but the parent node and the lower and upper sub-nodes are all set to nil.
func (node *BinTrieNode[E, V]) Clone() *BinTrieNode[E, V] {
	return toTrieNode(node.toBinTreeNode().clone())
}

// Equal returns whether the key matches the key of the given node
func (node *BinTrieNode[E, V]) Equal(other *BinTrieNode[E, V]) bool {
	if node == nil {
		return other == nil
	} else if other == nil {
		return false
	}
	return node == other || node.GetKey().Compare(other.GetKey()) == 0
}

// DeepEqual returns whether the key matches the key of the given node using Compare,
// and whether the value matches the other value using reflect.DeepEqual
func (node *BinTrieNode[E, V]) DeepEqual(other *BinTrieNode[E, V]) bool {
	if node == nil {
		return other == nil
	} else if other == nil {
		return false
	}
	return node.GetKey().Compare(other.GetKey()) == 0 && reflect.DeepEqual(node.GetValue(), other.GetValue())
}

// Compare returns -1, 0 or 1 if this node is less than, equal,
// or greater than the other, according to the key and the trie order.
func (node *BinTrieNode[E, V]) Compare(other *BinTrieNode[E, V]) int {
	if node == nil {
		if other == nil {
			return 0
		}
		return -1
	} else if other == nil {
		return 1
	}
	return node.GetKey().Compare(other.GetKey())
}

// For some reason Format must be here and not in addressTrieNode for nil node.
// It panics in fmt code either way, but if in here then it is handled by a recover() call in fmt properly.
// Seems to be a problem only in the debugger.
//
// Format implements the fmt.Formatter interface
func (node BinTrieNode[E, V]) Format(state fmt.State, verb rune) {
	node.format(state, verb)
}

func (node *BinTrieNode[E, V]) removeSubtree(result *opResult[E, V]) {
	result.deleted = node
	node.Clear()
}

func (node *BinTrieNode[E, V]) removeOp(result *opResult[E, V]) {
	result.deleted = node
	node.binTreeNode.Remove()
}

func (node *BinTrieNode[E, V]) handleContains(result *opResult[E, V]) bool {
	if result.op == containing {
		result.largestContaining = node // used by ElementContains
		return true
	} else if result.op == allContaining {
		result.addContaining(node) // used by ElementsContaining
		return true
	}
	result.smallestContaining = node // used by longest prefix match, which uses the lookup op
	return false
}

// Remaps the value for a node to a new value.
// This operation works on mapped values
// It returns true if a new node needs to be created (match is nil) or added (match is non-nil)
func (node *BinTrieNode[E, V]) remap(result *opResult[E, V], isMatch bool) bool {
	remapper := result.remapper
	change := node.cTracker.getCurrent()
	var existingValue V
	if isMatch {
		existingValue = node.GetValue()
	}

	result.existingValue = existingValue
	newValue, action := remapper(existingValue, isMatch)
	if action == doNothing {
		return false
	} else if action == removeNode {
		if isMatch {
			cTracker := node.cTracker
			if cTracker != nil && cTracker.changedSince(change) {
				panic("the tree has been modified by the remapper")
			}
			node.ClearValue()
			node.removeOp(result)
		}
		return false
	} else { // action is remapValue
		cTracker := node.cTracker
		if cTracker != nil && cTracker.changedSince(change) {
			panic("the tree has been modified by the remapper")
		}
		result.newValue = newValue
		return true
	}
}

func (node *BinTrieNode[E, V]) remapNonExisting(result *opResult[E, V]) *BinTrieNode[E, V] {
	if node.remap(result, false) {
		return node.createNew(result.key)
	}
	return nil
}

// this node matched when doing a lookup
func (node *BinTrieNode[E, V]) matched(result *opResult[E, V]) {
	result.existingNode = node
	result.nearestNode = node
}

func (node *BinTrieNode[E, V]) added(result *opResult[E, V]) {
	node.setNodeAdded(true)
	node.adjustCount(1)
	node.SetValue(result.newValue)
	node.cTracker.changed()
}

// only called when lower/higher and not floor/ceiling since for a match ends things for the latter.
func (node *BinTrieNode[E, V]) findNearestFromMatch(result *opResult[E, V]) {
	if result.nearestFloor {
		// looking for greatest element < queried address
		// since we have matched the address, we must go lower again,
		// and if we cannot, we must backtrack
		lower := node.GetLowerSubNode()
		if lower == nil {
			// no nearest node yet
			result.backtrackNode = node
		} else {
			var last *BinTrieNode[E, V]
			for {
				last = lower
				lower = lower.GetUpperSubNode()
				if lower == nil {
					break
				}
			}
			result.nearestNode = last
		}
	} else {
		// looking for smallest element > queried address
		upper := node.GetUpperSubNode()
		if upper == nil {
			// no nearest node yet
			result.backtrackNode = node
		} else {
			var last *BinTrieNode[E, V]
			for {
				last = upper
				upper = upper.GetLowerSubNode()
				if upper == nil {
					break
				}
			}
			result.nearestNode = last
		}
	}
}

func (node *BinTrieNode[E, V]) findNearest(result *opResult[E, V], differingBitIndex BitCount) {
	thisKey := node.GetKey()
	if differingBitIndex < thisKey.GetBitCount() && thisKey.IsOneBit(differingBitIndex) {
		// this element and all below are > than the query address
		if result.nearestFloor {
			// looking for greatest element < or <= queried address, so no need to go further
			// need to backtrack and find the last right turn to find node < than the query address again
			result.backtrackNode = node
		} else {
			// looking for smallest element > or >= queried address
			lower := node
			var last *BinTrieNode[E, V]
			for {
				last = lower
				lower = lower.GetLowerSubNode()
				if lower == nil {
					break
				}
			}
			result.nearestNode = last
		}
	} else {
		// this element and all below are < than the query address
		if result.nearestFloor {
			// looking for greatest element < or <= queried address
			upper := node
			var last *BinTrieNode[E, V]
			for {
				last = upper
				upper = upper.GetUpperSubNode()
				if upper == nil {
					break
				}
			}
			result.nearestNode = last
		} else {
			// looking for smallest element > or >= queried address, so no need to go further
			// need to backtrack and find the last left turn to find node > than the query address again
			result.backtrackNode = node
		}
	}
}

func (node *BinTrieNode[E, V]) cloneTreeBounds(bnds *bounds[E]) *BinTrieNode[E, V] {
	if node == nil {
		return nil
	}
	return toTrieNode(node.cloneTreeTrackerBounds(&changeTracker{}, &sync.Pool{
		New: func() any { return &opResult[E, V]{} },
	}, bnds))
}

// Clones the sub-tree starting with this node as root.
// The nodes are cloned, but their keys and values are not cloned.
func (node *BinTrieNode[E, V]) cloneTree() *BinTrieNode[E, V] {
	return node.cloneTreeBounds(nil)
}

// CloneTree clones the sub-tree starting with this node as root.
// The nodes are cloned, but their keys and values are not cloned.
func (node *BinTrieNode[E, V]) CloneTree() *BinTrieNode[E, V] {
	return node.cloneTree()
}

// Iterator returns an iterator that iterates through the elements of
// the sub-tree with this node as the root.
// The iteration is in sorted element order.
func (node *BinTrieNode[E, V]) Iterator() TrieKeyIterator[E] {
	return trieKeyIterator[E]{node.toBinTreeNode().iterator()}
}

// DescendingIterator returns an iterator that iterates through the elements of
// the subtrie with this node as the root.
// The iteration is in reverse sorted element order.
func (node *BinTrieNode[E, V]) DescendingIterator() TrieKeyIterator[E] {
	return trieKeyIterator[E]{node.toBinTreeNode().descendingIterator()}
}

// NodeIterator returns an iterator that iterates through the added nodes of
// the sub-tree with this node as the root, in forward or reverse tree order.
func (node *BinTrieNode[E, V]) NodeIterator(forward bool) TrieNodeIteratorRem[E, V] {
	return trieNodeIteratorRem[E, V]{node.toBinTreeNode().nodeIterator(forward)}
}

// AllNodeIterator returns an iterator that iterates through all the nodes of
// the sub-tree with this node as the root, in forward or reverse tree order.
func (node *BinTrieNode[E, V]) AllNodeIterator(forward bool) TrieNodeIteratorRem[E, V] {
	return trieNodeIteratorRem[E, V]{node.toBinTreeNode().allNodeIterator(forward)}
}

func (node *BinTrieNode[E, V]) blockSizeNodeIterator(lowerSubNodeFirst, addedNodesOnly bool) TrieNodeIteratorRem[E, V] {
	var size int
	reverseBlocksEqualSize := !lowerSubNodeFirst
	if addedNodesOnly {
		size = node.Size()
	}

	iter := newPriorityNodeIterator(
		size,
		addedNodesOnly,
		node.toBinTreeNode(),
		func(one, two E) int {
			val := BlockSizeCompare(one, two, reverseBlocksEqualSize)
			return -val
		})
	return trieNodeIteratorRem[E, V]{&iter}
}

// BlockSizeNodeIterator returns an iterator that iterates the added nodes,
// ordered by keys from largest prefix blocks (smallest prefix length)
// to smallest (largest prefix length) and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first,
// otherwise the reverse order is taken.
func (node *BinTrieNode[E, V]) BlockSizeNodeIterator(lowerSubNodeFirst bool) TrieNodeIteratorRem[E, V] {
	return node.blockSizeNodeIterator(lowerSubNodeFirst, true)
}

// BlockSizeAllNodeIterator returns an iterator that iterates all the nodes,
// ordered by keys from largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first,
// otherwise the reverse order
func (node *BinTrieNode[E, V]) BlockSizeAllNodeIterator(lowerSubNodeFirst bool) TrieNodeIteratorRem[E, V] {
	return node.blockSizeNodeIterator(lowerSubNodeFirst, false)
}

// BlockSizeCachingAllNodeIterator returns an iterator of all nodes,
// ordered by keys from largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// This iterator allows you to cache an object with subnodes so
// that when those nodes are visited the cached object can be retrieved.
func (node *BinTrieNode[E, V]) BlockSizeCachingAllNodeIterator() CachingTrieNodeIterator[E, V] {
	iter := newCachingPriorityNodeIterator(
		node.toBinTreeNode(),
		func(one, two E) int {
			val := BlockSizeCompare(one, two, false)
			return -val
		})
	return &cachingTrieNodeIterator[E, V]{&iter}
}

func (node *BinTrieNode[E, V]) ContainingFirstIterator(forwardSubNodeOrder bool) CachingTrieNodeIterator[E, V] {
	return &cachingTrieNodeIterator[E, V]{node.toBinTreeNode().containingFirstIterator(forwardSubNodeOrder)}
}

func (node *BinTrieNode[E, V]) ContainingFirstAllNodeIterator(forwardSubNodeOrder bool) CachingTrieNodeIterator[E, V] {
	return &cachingTrieNodeIterator[E, V]{node.toBinTreeNode().containingFirstAllNodeIterator(forwardSubNodeOrder)}
}

func (node *BinTrieNode[E, V]) ContainedFirstIterator(forwardSubNodeOrder bool) TrieNodeIteratorRem[E, V] {
	return trieNodeIteratorRem[E, V]{node.toBinTreeNode().containedFirstIterator(forwardSubNodeOrder)}
}

func (node *BinTrieNode[E, V]) ContainedFirstAllNodeIterator(forwardSubNodeOrder bool) TrieNodeIterator[E, V] {
	return trieNodeIterator[E, V]{node.toBinTreeNode().containedFirstAllNodeIterator(forwardSubNodeOrder)}
}

// TreeEqual returns whether the sub-tree represented by
// this node as the root node matches the given sub-tree,
// matching the trie keys using the Compare method
func (node *BinTrieNode[E, V]) TreeEqual(other *BinTrieNode[E, V]) bool {
	if other == node {
		return true
	} else if other.Size() != node.Size() {
		return false
	}

	these, others := node.Iterator(), other.Iterator()
	if these.HasNext() {
		for thisKey := these.Next(); these.HasNext(); thisKey = these.Next() {
			if thisKey.Compare(others.Next()) != 0 {
				return false
			}
		}
	}
	return true
}

// TreeDeepEqual returns whether the sub-tree represented by
// this node as the root node matches the given sub-tree,
// matching the nodes using DeepEqual
func (node *BinTrieNode[E, V]) TreeDeepEqual(other *BinTrieNode[E, V]) bool {
	if other == node {
		return true
	} else if other.Size() != node.Size() {
		return false
	}

	these, others := node.NodeIterator(true), other.NodeIterator(true)
	thisNode := these.Next()
	for ; thisNode != nil; thisNode = these.Next() {
		if thisNode.DeepEqual(others.Next()) {
			return false
		}
	}
	return true
}

// AsNewTrie creates a new sub-trie,
// copying the nodes starting with this node as root.
// The nodes are copies of the nodes in this sub-trie,
// but their keys and values are not copies.
func (node *BinTrieNode[E, V]) AsNewTrie() *BinTrie[E, V] {
	key := node.GetKey()
	trie := &BinTrie[E, V]{binTree[E, V]{}}
	rootKey := key.ToPrefixBlockLen(0)
	trie.setRoot(rootKey)
	root := trie.root
	newNode := node.cloneTreeTrackerBounds(root.cTracker, root.pool, nil)
	if rootKey.Compare(key) == 0 {
		root.setUpper(newNode.upper)
		root.setLower(newNode.lower)
		if node.IsAdded() {
			root.SetAdded()
		}
		root.SetValue(node.GetValue())
	} else if key.IsOneBit(0) {
		root.setUpper(newNode)
	} else {
		root.setLower(newNode)
	}
	root.storedSize = sizeUnknown
	return trie
}

// this node is newly inserted and added
func (node *BinTrieNode[E, V]) inserted(result *opResult[E, V]) {
	result.inserted = node
	node.added(result)
}

// this node previously existed but was not added til now
func (node *BinTrieNode[E, V]) existingAdded(result *opResult[E, V]) {
	result.existingNode = node
	result.added = node
	node.added(result)
}

func (node *BinTrieNode[E, V]) remapNonAdded(result *opResult[E, V]) {
	if node.remap(result, false) {
		node.existingAdded(result)
	}
}

func (node *BinTrieNode[E, V]) matchSubNode(bitsFollowing uint64, result *opResult[E, V]) *BinTrieNode[E, V] {
	newKey := result.key
	if !freezeRoot && node.IsEmpty() {
		if result.op == remap {
			node.remapNonAdded(result)
		} else if result.op == insert {
			node.setKey(newKey)
			node.existingAdded(result)
		}
	} else if bitsFollowing != 0 {
		upper := node.GetUpperSubNode()
		if upper == nil {
			// no match
			op := result.op
			if op == insert {
				upper = node.createNew(newKey)
				node.setUpper(upper)
				upper.inserted(result)
			} else if op == near {
				if result.nearestFloor {
					// With only one sub-node at most, normally that would mean this node must be added.
					// But there is one exception, when we are the non-added root node.
					// So must check for added here.
					if node.IsAdded() {
						result.nearestNode = node
					} else {
						// check if our lower sub-node is there and added.  It is underneath addr too.
						// find the highest node in that direction.
						lower := node.GetLowerSubNode()
						if lower != nil {
							res := lower
							next := res.GetUpperSubNode()
							for next != nil {
								res = next
								next = res.GetUpperSubNode()
							}
							result.nearestNode = res
						}
					}
				} else {
					result.backtrackNode = node
				}
			} else if op == remap {
				upper = node.remapNonExisting(result)
				if upper != nil {
					node.setUpper(upper)
					upper.inserted(result)
				}
			}
		} else {
			return upper
		}
	} else {
		// In most cases, however, there are more bits in newKey, the former, to look at.
		lower := node.GetLowerSubNode()
		if lower == nil {
			// no match
			op := result.op
			if op == insert {
				lower = node.createNew(newKey)
				node.setLower(lower)
				lower.inserted(result)
			} else if op == near {
				if result.nearestFloor {
					result.backtrackNode = node
				} else {
					// With only one sub-node at most, normally that would mean this node must be added.
					// But there is one exception, when we are the non-added root node.
					// So must check for added here.
					if node.IsAdded() {
						result.nearestNode = node
					} else {
						// check if our upper sub-node is there and added.  It is above addr too.
						// find the highest node in that direction.
						upper := node.GetUpperSubNode()
						if upper != nil {
							res := upper
							next := res.GetLowerSubNode()
							for next != nil {
								res = next
								next = res.GetLowerSubNode()
							}
							result.nearestNode = res
						}
					}
				}
			} else if op == remap {
				lower = node.remapNonExisting(result)
				if lower != nil {
					node.setLower(lower)
					lower.inserted(result)
				}
			}
		} else {
			return lower
		}
	}
	return nil
}

// traverses the tree, matching bits with prefix block nodes, until we can match no longer,
// at which point it completes the operation, whatever that operation is
func (node *BinTrieNode[E, V]) matchBitsFromIndex(bitIndex int, result *opResult[E, V]) {
	matchNode := node
	existingKey := node.GetKey()
	newKey := result.key
	if newKey.GetBitCount() != existingKey.GetBitCount() {
		panic("mismatched bit length between trie keys")
	}

	newKeyData := newKey.GetTrieKeyData()

	op := result.op
	simpleMatch := !(op == insert || op == near || op == remap)

	// having these allocated in result eliminates gc activity
	result.nodeComp.result = result
	result.comp = &result.nodeComp
	for {
		result.nodeComp.node = matchNode
		continueToNext, followingBitsFlag := newKey.MatchBits(existingKey, bitIndex, simpleMatch, result.comp, newKeyData)
		if continueToNext {
			// matched all node bits up the given count, so move into sub-nodes
			matchNode = matchNode.matchSubNode(followingBitsFlag, result)
			if matchNode == nil {
				// reached the end of the line
				break
			}
			// Matched a sub-node.
			// The sub-node was chosen according to the next bit.
			// That bit is therefore now a match,
			// so increment the matched bits by 1, and keep going.
			bitIndex = existingKey.GetPrefixLen().bitCount() + 1
			existingKey = matchNode.GetKey()
		} else {
			// reached the end of the line
			break
		}
	}
}

func (node *BinTrieNode[E, V]) matchBits(result *opResult[E, V]) {
	node.matchBitsFromIndex(0, result)
}

// The current node and the new node both become sub-nodes of a new block node taking the position of the current node.
func (node *BinTrieNode[E, V]) split(result *opResult[E, V], totalMatchingBits BitCount, newSubNode *BinTrieNode[E, V]) {
	newBlock := node.GetKey().ToPrefixBlockLen(totalMatchingBits)
	node.replaceToSub(newBlock, totalMatchingBits, newSubNode)
	newSubNode.inserted(result)
}

func (node *BinTrieNode[E, V]) remapNonExistingSplit(result *opResult[E, V], totalMatchingBits BitCount) {
	if node.remap(result, false) {
		node.split(result, totalMatchingBits, node.createNew(result.key))
	}
}

func (node *BinTrieNode[E, V]) handleSplitNode(result *opResult[E, V], totalMatchingBits BitCount) {
	op := result.op
	if op == insert {
		node.split(result, totalMatchingBits, node.createNew(result.key))
	} else if op == near {
		node.findNearest(result, totalMatchingBits)
	} else if op == remap {
		node.remapNonExistingSplit(result, totalMatchingBits)
	}
}

func (node *BinTrieNode[E, V]) doLookup(key E, longestPrefixMatch, contains bool) (res *BinTrieNode[E, V]) {
	var result *opResult[E, V]
	if node == nil {
		return nil
	}

	pool := node.pool
	if pool != nil {
		result = pool.Get().(*opResult[E, V])
		result.key = key
		result.op = lookup
	} else {
		result = &opResult[E, V]{
			key: key,
			op:  lookup,
		}
	}

	node.matchBits(result)
	if longestPrefixMatch {
		res = result.smallestContaining
	} else if contains {
		res = result.containedBy
	} else {
		res = result.existingNode
	}

	if pool != nil {
		result.clean()
		pool.Put(result)
	}
	return
}

func (node *BinTrieNode[E, V]) Get(key E) (V, bool) {
	var result *opResult[E, V]
	if node == nil {
		var v V
		return v, false
	}

	pool := node.pool
	if pool != nil {
		result = pool.Get().(*opResult[E, V])
		result.key = key
		result.op = lookup
	} else {
		result = &opResult[E, V]{
			key: key,
			op:  lookup,
		}
	}

	node.matchBits(result)
	resultNode := result.existingNode
	if pool != nil {
		result.clean()
		pool.Put(result)
	}

	if resultNode == nil {
		var v V
		return v, false
	}
	return resultNode.GetValue(), true
}

func (node *BinTrieNode[E, V]) Contains(addr E) bool {
	if node == nil {
		return false
	}

	var result *opResult[E, V]
	pool := node.pool
	if pool != nil {
		result = pool.Get().(*opResult[E, V])
		result.key = addr
		result.op = lookup
	} else {
		result = &opResult[E, V]{
			key: addr,
			op:  lookup,
		}
	}

	node.matchBits(result)
	res := result.exists
	if pool != nil {
		result.clean()
		pool.Put(result)
	}
	return res
}

func (node *BinTrieNode[E, V]) RemoveNode(key E) bool {
	if node == nil {
		return false
	}
	result := &opResult[E, V]{
		key: key,
		op:  insertedDelete,
	}
	node.matchBits(result)
	return result.exists
}

type nodeCompare[E TrieKey[E], V any] struct {
	result *opResult[E, V]
	node   *BinTrieNode[E, V]
}

func (comp nodeCompare[E, V]) MismatchCallbackRequired() bool {
	op := comp.result.op
	return op == insert || op == near || op == remap
}

func (comp nodeCompare[E, V]) BitsMatchPartially() bool {
	node, result := comp.node, comp.result
	if node.IsAdded() {
		node.handleContains(result)
		return result.op != containing // we can stop if we are "containing" since we have the answer
	}
	return true
}

type opResult[E TrieKey[E], V any] struct {
	key E
	// whether near is searching for a floor or ceiling
	// a floor is greatest element below addr
	// a ceiling is lowest element above addr
	nearestFloor bool
	// whether near cannot be an exact match
	nearExclusive bool
	op            operation
	// remaps values based on their current contents
	remapper func(val V, exists bool) (V, remapAction)
	// lookups:
	//
	// an inserted tree element matches the supplied argument
	// exists is set to true only for "added" nodes
	exists bool
	// the matching tree element, when doing a lookup operation, or the pre-existing node for an insert operation
	// existingNode is set for both added and not added nodes
	existingNode,
	// the closest tree element, when doing a near operation
	nearestNode,
	// if searching for a floor/lower, and the nearest node is above addr, then we must backtrack to get below
	// if searching for a ceiling/higher, and the nearest node is below addr, then we must backtrack to get above
	backtrackNode,
	// contained by:
	// this tree is contained by the supplied argument
	containedBy,
	// deletions:
	// this tree was deleted
	deleted *BinTrieNode[E, V]
	// contains:
	//
	// A linked list of the tree elements, from largest to smallest,
	// that contain the supplied argument, and the end of the list
	containing, containingEnd *PathNode[E, V]
	// Of the tree nodes with elements containing the subnet or address,
	// those with the smallest or largets subnet or address
	smallestContaining, largestContaining *BinTrieNode[E, V]
	// adds and puts:
	// new and existing values for add, put and remap operations
	newValue, existingValue V
	// this added tree node was newly created for an add
	inserted,
	// this added tree node previously existed but had not been added yet
	added,
	// this added tree node was already added to the trie
	//
	// for searching use
	//
	nodeComp nodeCompare[E, V]
	comp KeyCompareResult
}

func (result *opResult[E, V]) clean() {
	result.exists = false
	result.existingNode = nil
	result.nearestNode = nil
	result.backtrackNode = nil
	result.containedBy = nil
	result.containing = nil
	result.containingEnd = nil
	result.smallestContaining = nil
	result.largestContaining = nil
	// the remainder do not need cleaning,
	// only those fields used by ops that use pooling of opResult,
	// the "search" operations
}

func (result *opResult[E, V]) getContaining() *Path[E, V] {
	containing := result.containing
	if containing == nil {
		return &Path[E, V]{}
	}
	return &Path[E, V]{
		root: containing,
		leaf: result.containingEnd,
	}
}

// add to the list of tree elements that contain the supplied argument
func (result *opResult[E, V]) addContaining(containingSub *BinTrieNode[E, V]) {
	if containingSub.IsAdded() {
		node := &PathNode[E, V]{
			item:       containingSub.item,
			value:      containingSub.value,
			storedSize: 1,
			added:      true,
		}
		if result.containing == nil {
			result.containing = node
		} else {
			last := result.containingEnd
			last.next = node
			node.previous = last
			last.storedSize++
			for next := last.previous; next != nil; next = next.previous {
				next.storedSize++
			}
		}
		result.containingEnd = node
	}
}

type TrieKeyIterator[E TrieKey[E]] interface {
	HasNext
	Next() E
	// Remove removes the last iterated element from the underlying trie, and returns that element.
	// If there is no such element, it returns the zero value.
	Remove() E
}

type trieKeyIterator[E TrieKey[E]] struct {
	keyIterator[E]
}

func (iter trieKeyIterator[E]) Next() E {
	return iter.keyIterator.Next()
}

func (iter trieKeyIterator[E]) Remove() E {
	return iter.keyIterator.Remove()
}

type TrieNodeIterator[E TrieKey[E], V any] interface {
	HasNext
	Next() *BinTrieNode[E, V]
}

type TrieNodeIteratorRem[E TrieKey[E], V any] interface {
	TrieNodeIterator[E, V]
	// Remove removes the last iterated element from the underlying trie,
	// and returns that element.
	// If there is no such element, it returns the zero value.
	Remove() *BinTrieNode[E, V]
}

type trieNodeIteratorRem[E TrieKey[E], V any] struct {
	nodeIteratorRem[E, V]
}

func (iter trieNodeIteratorRem[E, V]) Next() *BinTrieNode[E, V] {
	return toTrieNode(iter.nodeIteratorRem.Next())
}

func (iter trieNodeIteratorRem[E, V]) Remove() *BinTrieNode[E, V] {
	return toTrieNode(iter.nodeIteratorRem.Remove())
}

type trieNodeIterator[E TrieKey[E], V any] struct {
	nodeIterator[E, V]
}

func (iter trieNodeIterator[E, V]) Next() *BinTrieNode[E, V] {
	return toTrieNode(iter.nodeIterator.Next())
}

type CachingTrieNodeIterator[E TrieKey[E], V any] interface {
	TrieNodeIteratorRem[E, V]
	CachingIterator
}

type cachingTrieNodeIterator[E TrieKey[E], V any] struct {
	cachingNodeIterator[E, V] // an interface
}

func (iter *cachingTrieNodeIterator[E, V]) Next() *BinTrieNode[E, V] {
	return toTrieNode(iter.cachingNodeIterator.Next())
}

func (iter *cachingTrieNodeIterator[E, V]) Remove() *BinTrieNode[E, V] {
	return toTrieNode(iter.cachingNodeIterator.Remove())
}

// BlockSizeCompare compares keys by block size and then by prefix value if block sizes are equal
func BlockSizeCompare[E TrieKey[E]](key1, key2 E, reverseBlocksEqualSize bool) int {
	if key2 == key1 {
		return 0
	}

	pref2 := key2.GetPrefixLen()
	pref1 := key1.GetPrefixLen()
	if pref2 != nil {
		if pref1 != nil {
			val := pref2.Len() - pref1.Len()
			if val == 0 {
				compVal := key2.Compare(key1)
				if reverseBlocksEqualSize {
					compVal = -compVal
				}
				return compVal
			}
			return val
		}
		return -1
	}

	if pref1 != nil {
		return 1
	}

	compVal := key2.Compare(key1)
	if reverseBlocksEqualSize {
		compVal = -compVal
	}
	return compVal
}

// TrieIncrement returns the next key according to the trie ordering.
// The zero value is returned when there is no next key.
func TrieIncrement[E TrieKey[E]](key E) (next E, hasNext bool) {
	prefLen := key.GetPrefixLen()
	if prefLen != nil {
		return key.ToMinUpper(), true
	}

	bitCount := key.GetBitCount()
	trailingBits := key.GetTrailingBitCount(false)
	if trailingBits < bitCount {
		return key.ToPrefixBlockLen(bitCount - (trailingBits + 1)), true
	}
	return
}

// TrieDecrement returns the previous key according to the trie ordering
// The zero value is returned when there is no previous key.
func TrieDecrement[E TrieKey[E]](key E) (next E, hasNext bool) {
	prefLen := key.GetPrefixLen()
	if prefLen != nil {
		return key.ToMaxLower(), true
	}

	bitCount := key.GetBitCount()
	trailingBits := key.GetTrailingBitCount(true)
	if trailingBits < bitCount {
		return key.ToPrefixBlockLen(bitCount - (trailingBits + 1)), true
	}
	return
}
