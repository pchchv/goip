package tree

import (
	"math/big"
	"strconv"
	"sync"
	"unsafe"
)

var one = bigOne()

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
