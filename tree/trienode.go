package tree

import (
	"fmt"
	"reflect"
	"unsafe"
)

const (
	doNothing remapAction = iota
	removeNode
	remapValue
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

type nodeCompare[E TrieKey[E], V any] struct {
	result *opResult[E, V]
	node   *BinTrieNode[E, V]
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
