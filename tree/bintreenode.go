package tree

import (
	"math/big"
	"strconv"
	"sync"
	"unsafe"
)

var (
	one        = bigOne()
	freezeRoot = true
)

type Key interface {
	comparable // needed by populateCacheItem
}

// C represents cached values in iterators.
type C any

type change struct {
	big   *big.Int
	small uint64
}

func (c change) Equal(c2 change) bool {
	if c.small == c2.small {
		if c.big == nil {
			return c2.big == nil
		} else if c2.big != nil {
			return c.big.Cmp(c2.big) == 0
		}
	}
	return false
}

func (c *change) increment() {
	val := c.small
	val++
	if val == 0 {
		if c.big == nil {
			c.big = bigOne()
		} else {
			c.big.Add(c.big, one)
		}
	}
	c.small = val
}

func (c change) String() string {
	return c.big.String() + " " + strconv.FormatUint(c.small, 10)
}

type changeTracker struct {
	currentChange change
	watched       bool
}

func (c *changeTracker) changed() {
	if c.watched {
		c.watched = false
		c.currentChange.increment()
	}
	// else nobody is watching the current change, so no need to do anything
}

func (c *changeTracker) changedSince(otherChange change) bool {
	return !c.currentChange.Equal(otherChange)
}

func (c *changeTracker) getCurrent() change {
	c.watched = true
	return c.currentChange
}

func (c *changeTracker) String() string {
	return "current change: " + c.currentChange.String()
}

type bounds[E Key] struct {
}

func (b *bounds[E]) isInBounds(_ E) bool {
	return true
}

func (b *bounds[E]) isWithinLowerBound(_ E) bool {
	return true
}

func (b *bounds[E]) isBelowLowerBound(_ E) bool {
	return true
}

func (b *bounds[E]) isWithinUpperBound(_ E) bool {
	return true
}

func (b *bounds[E]) isAboveUpperBound(_ E) bool {
	return true
}

type binTreeNode[E Key, V any] struct {
	item       E // key for the node
	value      V // only for associative trie nodes
	storedSize int
	added      bool       // some nodes represent elements added to the tree and others are nodes generated internally when other nodes are added
	pool       *sync.Pool // used to store opResult objects for search operations
	cTracker   *changeTracker
	parent     *binTreeNode[E, V]
	lower      *binTreeNode[E, V]
	upper      *binTreeNode[E, V]
	self       *binTreeNode[E, V]
}

func (node *binTreeNode[E, V]) setAddr() {
	node.self = (*binTreeNode[E, V])(hideptr(unsafe.Pointer(node)))
}

func (node *binTreeNode[E, V]) checkCopy() {
	if node != nil && node.self != nil && node.self != node {
		panic("attempting to modify trie with a copied node")
	}
}

func (node *binTreeNode[E, V]) getChangeTracker() *changeTracker {
	if node == nil {
		return nil
	}
	return node.cTracker
}

// when FREEZE_ROOT is true, this is never called (and FREEZE_ROOT is always true)
func (node *binTreeNode[E, V]) setKey(item E) {
	node.item = item
}

// Gets the key used for placing the node in the tree.
func (node *binTreeNode[E, V]) GetKey() (key E) {
	if node != nil {
		key = node.item
	}
	return
}

// SetValue assigns a value to the node, overwriting any previous value
func (node *binTreeNode[E, V]) SetValue(val V) {
	// new value assignment
	node.value = val
}

// GetValue returns the value assigned to the node
func (node *binTreeNode[E, V]) GetValue() (val V) {
	if node != nil {
		val = node.value
	}
	return
}

func (node *binTreeNode[E, V]) ClearValue() {
	var v V
	// new value assignment
	node.value = v
}

// IsRoot returns whether this is the root of the backing tree.
func (node *binTreeNode[E, V]) IsRoot() bool {
	return node != nil && node.parent == nil
}

// Gets the node from which this node is a direct child node,
// or nil if this is the root.
func (node *binTreeNode[E, V]) getParent() (parent *binTreeNode[E, V]) {
	if node != nil {
		parent = node.parent
	}
	return
}

func (node *binTreeNode[E, V]) setParent(parent *binTreeNode[E, V]) {
	node.parent = parent
}

// Gets the direct child node whose key is largest in value
func (node *binTreeNode[E, V]) getUpperSubNode() (upper *binTreeNode[E, V]) {
	if node != nil {
		upper = node.upper
	}
	return
}

// Gets the direct child node whose key is smallest in value
func (node *binTreeNode[E, V]) getLowerSubNode() (lower *binTreeNode[E, V]) {
	if node != nil {
		lower = node.lower
	}
	return
}

func (node *binTreeNode[E, V]) setUpper(upper *binTreeNode[E, V]) {
	node.upper = upper
	if upper != nil {
		upper.setParent(node)
	}
}

func (node *binTreeNode[E, V]) setLower(lower *binTreeNode[E, V]) {
	node.lower = lower
	if lower != nil {
		lower.setParent(node)
	}
}

// IsAdded returns whether the node was "added".
// Some binary tree nodes are considered "added" and others are not.
// Those nodes created for key elements added to the tree are "added" nodes.
// Those that are not added are those nodes created to serve as junctions for the added nodes.
// Only added elements contribute to the size of a tree.
// When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
// which is when an added node has less than two added sub-nodes.
func (node *binTreeNode[E, V]) IsAdded() bool {
	return node != nil && node.added
}

func (node *binTreeNode[E, V]) setNodeAdded(added bool) {
	node.added = added
}

func (node *binTreeNode[E, V]) adjustCount(delta int) {
	if delta != 0 {
		thisNode := node
		for {
			thisNode.storedSize += delta
			thisNode = thisNode.getParent()
			if thisNode == nil {
				break
			}
		}
	}
}

// SetAdded makes this node an added node,
// which is equivalent to adding the corresponding key to the tree.
// If the node is already an added node,
// this method has no effect.
// You cannot set an added node to non-added,
// for that you should Remove the node from the tree by calling Remove.
// A non-added node will only remain in the tree if it needs to in the tree.
func (node *binTreeNode[E, V]) SetAdded() {
	if !node.added {
		node.setNodeAdded(true)
		node.adjustCount(1)
	}
}

func (node *binTreeNode[E, V]) removed() {
	node.adjustCount(-1)
	node.setNodeAdded(false)
	node.cTracker.changed()
	node.ClearValue()
}

func (node *binTreeNode[E, V]) replaceThisRoot(replacement *binTreeNode[E, V]) {
	if replacement == nil {
		node.setNodeAdded(false)
		node.setUpper(nil)
		node.setLower(nil)
		if !freezeRoot {
			var e E
			node.setKey(e)
			// here we'd need to replace with the default root (ie call setKey with key of 0.0.0.0/0 or ::/0 or 0:0:0:0:0:0)
		}
		node.storedSize = 0
		node.ClearValue()
	} else {
		// We never go here when FREEZE_ROOT is true
		node.setNodeAdded(replacement.IsAdded())
		node.setUpper(replacement.getUpperSubNode())
		node.setLower(replacement.getLowerSubNode())
		node.setKey(replacement.GetKey())
		node.storedSize = replacement.storedSize
		node.SetValue(replacement.GetValue())
	}
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

// This hideptr trick is used in strings.Builder
// to trick escape analysis to ensure that this self-referential pointer
// does not cause automatic heap allocation
// cannot hurt to use it
//
//go:nosplit
//go:nocheckptr
func hideptr(p unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) ^ 0)
}
