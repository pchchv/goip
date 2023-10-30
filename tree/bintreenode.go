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

func (node *binTreeNode[E, V]) adjustTree(parent, replacement *binTreeNode[E, V], additionalSizeAdjustment int, replacedUpper bool) {
	sizeAdjustment := -node.storedSize
	if replacement == nil {
		if !parent.IsAdded() && (!freezeRoot || !parent.IsRoot()) {
			parent.storedSize += sizeAdjustment
			var parentReplacement *binTreeNode[E, V]
			if replacedUpper {
				parentReplacement = parent.getLowerSubNode()
			} else {
				parentReplacement = parent.getUpperSubNode()
			}
			parent.replaceThisRecursive(parentReplacement, sizeAdjustment)
		} else {
			parent.adjustCount(sizeAdjustment + additionalSizeAdjustment)
		}
	} else {
		parent.adjustCount(replacement.storedSize + sizeAdjustment + additionalSizeAdjustment)
	}
	node.setParent(nil)
}

func (node *binTreeNode[E, V]) replaceThisRecursive(replacement *binTreeNode[E, V], additionalSizeAdjustment int) {
	if node.IsRoot() {
		node.replaceThisRoot(replacement)
		return
	}

	parent := node.getParent()
	if parent.getUpperSubNode() == node {
		// we adjust parents first, using the size and other characteristics of ourselves,
		// before the parent severs the link to ourselves with the call to setUpper,
		// since the setUpper call is allowed to change the characteristics of the child,
		// and in some cases this does adjust the size of the child.
		node.adjustTree(parent, replacement, additionalSizeAdjustment, true)
		parent.setUpper(replacement)
	} else if parent.getLowerSubNode() == node {
		node.adjustTree(parent, replacement, additionalSizeAdjustment, false)
		parent.setLower(replacement)
	} else {
		panic("corrupted trie") // will never reach here
	}
}

// Makes the parent of this point to something else, thus removing this and all sub-nodes from the tree
func (node *binTreeNode[E, V]) replaceThis(replacement *binTreeNode[E, V]) {
	node.replaceThisRecursive(replacement, 0)
	node.cTracker.changed()
}

// Remove removes this node from the collection of added nodes,
// and also removes from the tree if possible.
// If it has two sub-nodes,
// it cannot be removed from the tree,
// in which case it is marked as not "added",
// nor is it counted in the tree size.
// Only added nodes can be removed from the tree.
// If this node is not added, this method does nothing.
func (node *binTreeNode[E, V]) Remove() {
	node.checkCopy()
	if !node.IsAdded() {
		return
	} else if freezeRoot && node.IsRoot() {
		node.removed()
	} else if node.getUpperSubNode() == nil {
		node.replaceThis(node.getLowerSubNode()) // also handles case of lower == nil
	} else if node.getLowerSubNode() == nil {
		node.replaceThis(node.getUpperSubNode())
	} else { // has two sub-nodes
		node.removed()
	}
}

// Clear removes this node and all sub-nodes from
// the sub-tree with this node as the root,
// after which isEmpty() will return true.
func (node *binTreeNode[E, V]) Clear() {
	node.checkCopy()
	if node != nil {
		node.replaceThis(nil)
	}
}

// IsEmpty returns where there are not any elements in the sub-tree with this node as the root.
func (node *binTreeNode[E, V]) IsEmpty() bool {
	return !node.IsAdded() && node.getUpperSubNode() == nil && node.getLowerSubNode() == nil
}

// IsLeaf returns whether this node is in the tree (a node for which IsAdded() is true)
// and there are no elements in the sub-tree with this node as the root.
func (node *binTreeNode[E, V]) IsLeaf() bool {
	return node.IsAdded() && node.getUpperSubNode() == nil && node.getLowerSubNode() == nil
}

func (node *binTreeNode[E, V]) nextAdded(end *binTreeNode[E, V], nextOperator func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V]) *binTreeNode[E, V] {
	return nextTest(node, end, nextOperator, (*binTreeNode[E, V]).IsAdded)
}

//	in-order
//
//				8x
//		4x					12x
//	2x		6x			10x		14x
//
// 1x 3x		5x 7x		9x 11x	13x 15x
func (node *binTreeNode[E, V]) nextNodeBounded(bound *binTreeNode[E, V]) *binTreeNode[E, V] {
	next := node.getUpperSubNode()
	if next != nil {
		for {
			nextLower := next.getLowerSubNode()
			if nextLower == nil {
				return next
			}
			next = nextLower
		}
	} else {
		next = node.getParent()
		if next == bound {
			return nil
		}
		current := node
		for next != nil && current == next.getUpperSubNode() {
			current = next
			next = next.getParent()
			if next == bound {
				return nil
			}
		}
	}
	return next
}

// nextAddedNode returns the next node in the tree that is an added node,
// following the tree order,
// or nil if there is no such node.
func (node *binTreeNode[E, V]) nextAddedNode() *binTreeNode[E, V] {
	return node.nextAdded(nil, (*binTreeNode[E, V]).nextNodeBounded)
}

// firstNode returns the first (lowest valued)
// node in the sub-tree originating from this node.
func (node *binTreeNode[E, V]) firstNode() *binTreeNode[E, V] {
	first := node
	for {
		lower := first.getLowerSubNode()
		if lower == nil {
			return first
		}
		first = lower
	}
}

// firstAddedNode returns the first (lowest valued) added node in
// the sub-tree originating from this node,
// or nil if there are no added entries in this tree or sub-tree
func (node *binTreeNode[E, V]) firstAddedNode() *binTreeNode[E, V] {
	first := node.firstNode()
	if first.IsAdded() {
		return first
	}
	return first.nextAddedNode()
}

// lastNode returns the last (highest valued)
// node in the sub-tree originating from this node.
func (node *binTreeNode[E, V]) lastNode() *binTreeNode[E, V] {
	last := node
	for {
		upper := last.getUpperSubNode()
		if upper == nil {
			return last
		}
		last = upper
	}
}

//	reverse order
//
//				8x
//		12x					4x
//	14x		10x			6x		2x
//
// 15x 13x	11x 9x		7x 5x	3x 1x
func (node *binTreeNode[E, V]) previousNodeBounded(bound *binTreeNode[E, V]) *binTreeNode[E, V] {
	previous := node.getLowerSubNode()
	if previous != nil {
		for {
			previousUpper := previous.getUpperSubNode()
			if previousUpper == nil {
				break
			}
			previous = previousUpper
		}
	} else {
		previous = node.getParent()
		if previous == bound {
			return nil
		}
		current := node
		for previous != nil && current == previous.getLowerSubNode() {
			current = previous
			previous = previous.getParent()
			if previous == bound {
				return nil
			}
		}
	}
	return previous
}

// previousAddedNode returns the previous node in the tree that is an added node,
// following the tree order in reverse,
// or nil if there is no such node.
func (node *binTreeNode[E, V]) previousAddedNode() *binTreeNode[E, V] {
	return node.nextAdded(nil, (*binTreeNode[E, V]).previousNodeBounded)
}

// lastAddedNode returns the last (highest valued) added node in
// the sub-tree originating from this node,
// or nil if there are no added entries in this tree or sub-tree
func (node *binTreeNode[E, V]) lastAddedNode() *binTreeNode[E, V] {
	last := node.lastNode()
	if last.IsAdded() {
		return last
	}
	return last.previousAddedNode()
}

func (node *binTreeNode[E, V]) firstPostOrderNode() *binTreeNode[E, V] {
	next := node
	var nextNext *binTreeNode[E, V]
	for {
		nextNext = next.getLowerSubNode()
		if nextNext == nil {
			nextNext = next.getUpperSubNode()
			if nextNext == nil {
				return next
			}
		}
		next = nextNext
	}
}

func (node *binTreeNode[E, V]) lastPreOrderNode() *binTreeNode[E, V] {
	next := node
	var nextNext *binTreeNode[E, V]
	for {
		nextNext = next.getUpperSubNode()
		if nextNext == nil {
			nextNext = next.getLowerSubNode()
			if nextNext == nil {
				return next
			}
		}
		next = nextNext
	}
}

// nextNode returns the node that follows this node following the tree order
func (node *binTreeNode[E, V]) nextNode() *binTreeNode[E, V] {
	return node.nextNodeBounded(nil)
}

// previousNode returns the node that precedes this node following the tree order.
func (node *binTreeNode[E, V]) previousNode() *binTreeNode[E, V] {
	return node.previousNodeBounded(nil)
}

//	pre order
//				1x
//		2x						9x
//
// 3x		6x				10x		13x
// 4x 5x		7x 8x		11x 12x		14x 15x
// this one starts from root, ends at last node, all the way right
func (node *binTreeNode[E, V]) nextPreOrderNode(end *binTreeNode[E, V]) *binTreeNode[E, V] {
	next := node.getLowerSubNode()
	if next == nil {
		// cannot go left/lower
		next = node.getUpperSubNode()
		if next == nil {
			// cannot go right/upper
			current := node
			next = node.getParent()
			// so instead, keep going up until we can go right
			for next != nil {
				if next == end {
					return nil
				}
				if current == next.getLowerSubNode() {
					// parent is higher
					nextNext := next.getUpperSubNode()
					if nextNext != nil {
						return nextNext
					}
				}
				current = next
				next = next.getParent()
			}
		}
	}
	return next
}

//	reverse post order
//				1x
//		9x					2x
//	13x		10x			6x		3x
//
// 15x 14x	12x 11x		8x 7x	5x 4x
// this one starts from root, ends at first node, all the way left
// this is the mirror image of nextPreOrderNode, so no comments
func (node *binTreeNode[E, V]) previousPostOrderNode(end *binTreeNode[E, V]) *binTreeNode[E, V] {
	next := node.getUpperSubNode()
	if next == nil {
		next = node.getLowerSubNode()
		if next == nil {
			current := node
			next = node.getParent()
			for next != nil {
				if next == end {
					return nil
				}
				if current == next.getUpperSubNode() {
					nextNext := next.getLowerSubNode()
					if nextNext != nil {
						next = nextNext
						break
					}
				}
				current = next
				next = next.getParent()
			}
		}
	}
	return next
}

//	reverse pre order
//
//				15x
//		14x					7x
//	13x		10x			6x		3x
//
// 12x 11x	9x 8x		5x 4x	2x 1x
//
// this one starts from last node, all the way right, ends at root
// this is the mirror image of nextPostOrderNode, so no comments
func (node *binTreeNode[E, V]) previousPreOrderNode(end *binTreeNode[E, V]) *binTreeNode[E, V] {
	next := node.getParent()
	if next == nil || next == end {
		return nil
	}

	if next.getLowerSubNode() == node {
		return next
	}

	nextNext := next.getLowerSubNode()
	if nextNext == nil {
		return next
	}
	
	next = nextNext
	for {
		nextNext = next.getUpperSubNode()
		if nextNext == nil {
			nextNext = next.getLowerSubNode()
			if nextNext == nil {
				return next
			}
		}
		next = nextNext
	}
}

//	post order
//				15x
//		7x					14x
//	3x		6x			10x		13x
//
// 1x 2x		4x 5x		8x 9x	11x 12x
// this one starts from first node, all the way left, ends at root
func (node *binTreeNode[E, V]) nextPostOrderNode(end *binTreeNode[E, V]) *binTreeNode[E, V] {
	next := node.getParent()
	if next == nil || next == end {
		return nil
	}

	if next.getUpperSubNode() == node {
		// we are the upper sub-node, so parent is next
		return next
	}

	// we are the lower sub-node
	nextNext := next.getUpperSubNode()
	if nextNext == nil {
		// parent has no upper sub-node, so parent is next
		return next
	}

	// go to parent's upper sub-node
	next = nextNext
	// now go all the way down until we can go no further, favoring left/lower turns over right/upper
	for {
		nextNext = next.getLowerSubNode()
		if nextNext == nil {
			nextNext = next.getUpperSubNode()
			if nextNext == nil {
				return next
			}
		}
		next = nextNext
	}
}

func (node *binTreeNode[E, V]) nextInBounds(end *binTreeNode[E, V], nextOperator func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V], bnds *bounds[E]) *binTreeNode[E, V] {
	return nextTest(node, end, nextOperator, func(current *binTreeNode[E, V]) bool {
		return bnds.isInBounds(current.GetKey())
	})
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

func nextTest[E Key, V any](current, end *binTreeNode[E, V], nextOperator func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V], tester func(current *binTreeNode[E, V]) bool) *binTreeNode[E, V] {
	for {
		current = nextOperator(current, end)
		if current == end || current == nil {
			return nil
		}
		if tester(current) {
			break
		}
	}
	return current
}
