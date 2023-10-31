package tree

const (
	ipv6BitCount = 128
	stackSize    = ipv6BitCount + 2 // 129 for prefixes /0 to /128 and also 1 more for non-prefixed
)

type HasNext interface {
	HasNext() bool
}

type nodeIterator[E Key, V any] interface {
	HasNext
	Next() *binTreeNode[E, V]
}

type nodeIteratorRem[E Key, V any] interface {
	nodeIterator[E, V]
	// Remove removes the last iterated element from the underlying trie, and returns that element.
	// If there is no such element, it returns nil.
	Remove() *binTreeNode[E, V]
}

type binTreeNodeIterator[E Key, V any] struct {
	// takes current node and end as args
	operator      func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) (nextNode *binTreeNode[E, V])
	current       *binTreeNode[E, V]
	next          *binTreeNode[E, V]
	end           *binTreeNode[E, V] // a non-nil node that denotes the end, possibly parent of the starting node
	cTracker      *changeTracker
	currentChange change
}

func (iter *binTreeNodeIterator[E, V]) toNext(current *binTreeNode[E, V]) *binTreeNode[E, V] {
	return iter.operator(current, iter.end)
}

func (iter *binTreeNodeIterator[E, V]) getStart(start, end *binTreeNode[E, V], bounds *bounds[E], addedOnly bool) *binTreeNode[E, V] {
	if start == end || start == nil {
		return nil
	}

	if !addedOnly || start.IsAdded() {
		if bounds == nil || bounds.isInBounds(start.GetKey()) {
			return start
		}
	}

	return iter.toNext(start)
}

func (iter *binTreeNodeIterator[E, V]) setChangeTracker(ctracker *changeTracker) {
	if ctracker != nil {
		iter.cTracker, iter.currentChange = ctracker, ctracker.getCurrent()
	}
}

func (iter *binTreeNodeIterator[E, V]) HasNext() bool {
	return iter.next != nil
}

func (iter *binTreeNodeIterator[E, V]) Next() *binTreeNode[E, V] {
	if !iter.HasNext() {
		return nil
	}

	cTracker := iter.cTracker
	if cTracker != nil && cTracker.changedSince(iter.currentChange) {
		panic("the tree has been modified since the iterator was created")
	}

	iter.current = iter.next
	iter.next = iter.toNext(iter.next)
	return iter.current
}

func (iter *binTreeNodeIterator[E, V]) Remove() *binTreeNode[E, V] {
	if iter.current == nil {
		return nil
	}

	cTracker := iter.cTracker
	if cTracker != nil && cTracker.changedSince(iter.currentChange) {
		panic("the tree has been modified since the iterator was created")
	}

	result := iter.current
	result.Remove()
	iter.current = nil
	if cTracker != nil {
		iter.currentChange = cTracker.getCurrent()
	}

	return result
}

type subNodeCachingIterator[E Key, V any] struct {
	binTreeNodeIterator[E, V]
	cacheItem  C
	nextKey    E
	nextCached C
	stack      []C
	stackIndex int
	bnds       *bounds[E]
	addedOnly  bool
	isForward  bool
	// Both these fields are not really necessary because
	// the caching and removal functionality should not be exposed when it is not usable.
	// The interfaces will not include the caching and Remove() methods in the cases where they are not usable.
	// So these fields are both runtime checks for coding errors.
	allowCaching bool
	allowRemove  bool
}

func (iter *subNodeCachingIterator[E, V]) Next() *binTreeNode[E, V] {
	result := iter.binTreeNodeIterator.Next()
	if result != nil && iter.allowCaching {
		iter.populateCacheItem(result)
	}
	return result
}

func (iter *subNodeCachingIterator[E, V]) GetCached() C {
	if !iter.allowCaching {
		panic("no caching allowed, this code path should not be accessible")
	}
	return iter.cacheItem
}

func (iter *subNodeCachingIterator[E, V]) populateCacheItem(current *binTreeNode[E, V]) {
	nextKey := iter.nextKey
	if current.GetKey() == nextKey {
		iter.cacheItem = iter.nextCached
		iter.nextCached = nil
	} else {
		stack := iter.stack
		if stack != nil {
			stackIndex := iter.stackIndex
			if stackIndex >= 0 && stack[stackIndex] == current.GetKey() {
				iter.cacheItem = stack[stackIndex+stackSize].(C)
				stack[stackIndex+stackSize] = nil
				stack[stackIndex] = nil
				iter.stackIndex--
			} else {
				iter.cacheItem = nil
			}
		} else {
			iter.cacheItem = nil
		}
	}
}

func (iter *subNodeCachingIterator[E, V]) Remove() *binTreeNode[E, V] {
	if !iter.allowRemove {
		// Example:
		// Suppose we are at right sub-node, just visited left.  Next node is parent, but not added.
		// When right is removed, so is the parent, so that the left takes its place.
		// But parent is our next node.  Now our next node is invalid.  So we are lost.
		// This is avoided for iterators that are "added" only.
		panic("no removal allowed, this code path should not be accessible")
	}
	return iter.binTreeNodeIterator.Remove()
}

func (iter *subNodeCachingIterator[E, V]) checkCaching() {
	if !iter.allowCaching {
		panic("no caching allowed, this code path should not be accessible")
	}
}

// the sub-node will be the next visited node
func (iter *subNodeCachingIterator[E, V]) cacheWithFirstSubNode(object C) bool {
	iter.checkCaching()
	if iter.current != nil {
		var firstNode *binTreeNode[E, V]
		if iter.isForward {
			firstNode = iter.current.getLowerSubNode()
		} else {
			firstNode = iter.current.getUpperSubNode()
		}
		if firstNode != nil {
			if (iter.addedOnly && !firstNode.IsAdded()) || (iter.bnds != nil && !iter.bnds.isInBounds(firstNode.GetKey())) {
				firstNode = iter.operator(firstNode, iter.current)
			}
			if firstNode != nil {
				// the lower sub-node is always next if it exists
				iter.nextKey = firstNode.GetKey()
				iter.nextCached = object
				return true
			}
		}
	}
	return false
}

// the sub-node will only be the next visited node if there is no other sub-node,
// otherwise it might not be visited for a while
func (iter *subNodeCachingIterator[E, V]) cacheWithSecondSubNode(object C) bool {
	iter.checkCaching()
	if iter.current != nil {
		var secondNode *binTreeNode[E, V]
		if iter.isForward {
			secondNode = iter.current.getUpperSubNode()
		} else {
			secondNode = iter.current.getLowerSubNode()
		}
		if secondNode != nil {
			if (iter.addedOnly && !secondNode.IsAdded()) || (iter.bnds != nil && !iter.bnds.isInBounds(secondNode.GetKey())) {
				secondNode = iter.operator(secondNode, iter.current)
			}
			if secondNode != nil {
				// if there is no lower node, we can use the nextCached field since upper is next when no lower sub-node
				var firstNode *binTreeNode[E, V]
				if iter.isForward {
					firstNode = iter.current.getLowerSubNode()
				} else {
					firstNode = iter.current.getUpperSubNode()
				}
				if firstNode == nil {
					iter.nextKey = secondNode.GetKey()
					iter.nextCached = object
				} else {
					if iter.stack == nil {
						iter.stack = make([]C, stackSize<<1)
					}
					iter.stackIndex++
					iter.stack[iter.stackIndex] = secondNode.GetKey()
					iter.stack[iter.stackIndex+stackSize] = object
				}
				return true
			}
		}
	}
	return false
}

func (iter *subNodeCachingIterator[E, V]) CacheWithLowerSubNode(object C) bool {
	iter.checkCaching()
	if iter.isForward {
		return iter.cacheWithFirstSubNode(object)
	}
	return iter.cacheWithSecondSubNode(object)

}

func (iter *subNodeCachingIterator[E, V]) CacheWithUpperSubNode(object C) bool {
	iter.checkCaching()
	if iter.isForward {
		return iter.cacheWithSecondSubNode(object)
	}
	return iter.cacheWithFirstSubNode(object)
}

type keyIterator[E Key] interface {
	HasNext
	Next() E
	// Remove removes the last iterated element from the underlying trie, and returns that element.
	// If there is no such element, it returns nil.
	Remove() E
}

type binTreeKeyIterator[E Key, V any] struct {
	nodeIteratorRem[E, V]
}

func (iter binTreeKeyIterator[E, V]) Next() E {
	return iter.nodeIteratorRem.Next().GetKey()
}

func (iter binTreeKeyIterator[E, V]) Remove() E {
	return iter.nodeIteratorRem.Remove().GetKey()
}

type CachingIterator interface {
	// GetCached returns an object previously cached with the current iterated node.
	// After Next has returned a node,
	// if an object was cached by a call to CacheWithLowerSubNode or CacheWithUpperSubNode
	// was called when that node's parent was previously returned by Next,
	// then this returns that cached object.
	GetCached() C
	// CacheWithLowerSubNode caches an object with the lower sub-node of the current iterated node.
	// After Next has returned a node,
	// calling this method caches the provided object with the lower sub-node so that it can
	// be retrieved with GetCached when the lower sub-node is visited later.
	//
	// Returns false if it could not be cached, either because the node has since been removed with a call to Remove,
	// because Next has not been called yet, or because there is no lower sub node for the node previously returned by  Next.
	//
	// The caching and retrieval is done in constant time.
	CacheWithLowerSubNode(C) bool
	// CacheWithUpperSubNode caches an object with the upper sub-node of the current iterated node.
	// After Next has returned a node,
	// calling this method caches the provided object with the upper sub-node so that it can
	// be retrieved with GetCached when the upper sub-node is visited later.
	//
	// Returns false if it could not be cached, either because the node has since been removed with a call to Remove,
	// because Next has not been called yet, or because there is no upper sub node for the node previously returned by Next.
	//
	// The caching and retrieval is done in constant time.
	CacheWithUpperSubNode(C) bool
}

func newNodeIterator[E Key, V any](forward, addedOnly bool, start, end *binTreeNode[E, V], ctracker *changeTracker) nodeIteratorRem[E, V] {
	var nextOperator func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V]
	if forward {
		nextOperator = (*binTreeNode[E, V]).nextNodeBounded
	} else {
		nextOperator = (*binTreeNode[E, V]).previousNodeBounded
	}

	if addedOnly {
		wrappedOp := nextOperator
		nextOperator = func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) *binTreeNode[E, V] {
			return currentNode.nextAdded(endNode, wrappedOp)
		}
	}

	res := binTreeNodeIterator[E, V]{end: end}
	res.setChangeTracker(ctracker)
	res.operator = nextOperator
	res.next = res.getStart(start, end, nil, addedOnly)
	return &res
}

// The caching only useful when in reverse order, since you have to visit parent nodes first for it to be useful.
func newPostOrderNodeIterator[E Key, V any](forward, addedOnly bool, start, end *binTreeNode[E, V], ctracker *changeTracker) subNodeCachingIterator[E, V] {
	return newPostOrderNodeIteratorBounded(
		nil,
		forward, addedOnly,
		start, end,
		ctracker)
}

func newSubNodeCachingIterator[E Key, V any](
	bnds *bounds[E],
	forward, addedOnly bool,
	start, end *binTreeNode[E, V],
	ctracker *changeTracker,
	nextOperator func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V],
	allowCaching,
	allowRemove bool,
) subNodeCachingIterator[E, V] {
	res := subNodeCachingIterator[E, V]{
		allowCaching:        allowCaching,
		allowRemove:         allowRemove,
		stackIndex:          -1,
		bnds:                bnds,
		isForward:           forward,
		addedOnly:           addedOnly,
		binTreeNodeIterator: binTreeNodeIterator[E, V]{end: end},
	}
	res.setChangeTracker(ctracker)
	res.operator = nextOperator
	res.next = res.getStart(start, end, bnds, addedOnly)
	return res
}

func newPostOrderNodeIteratorBounded[E Key, V any](bnds *bounds[E], forward, addedOnly bool, start, end *binTreeNode[E, V], ctracker *changeTracker) subNodeCachingIterator[E, V] {
	var op func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V]
	if forward {
		op = (*binTreeNode[E, V]).nextPostOrderNode
	} else {
		op = (*(binTreeNode[E, V])).previousPostOrderNode
	}

	// do the added-only filter first, because it is simpler
	if addedOnly {
		wrappedOp := op
		op = func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) *binTreeNode[E, V] {
			return currentNode.nextAdded(endNode, wrappedOp)
		}
	}

	if bnds != nil {
		wrappedOp := op
		op = func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) *binTreeNode[E, V] {
			return currentNode.nextInBounds(endNode, wrappedOp, bnds)
		}
	}

	return newSubNodeCachingIterator[E, V](
		bnds,
		forward, addedOnly,
		start, end,
		ctracker,
		op,
		!forward,
		!forward || addedOnly)
}

// The caching only useful when in forward order, since you have to visit parent nodes first for it to be useful.
func newPreOrderNodeIterator[E Key, V any](forward, addedOnly bool, start, end *binTreeNode[E, V], ctracker *changeTracker) subNodeCachingIterator[E, V] {
	return newPreOrderNodeIteratorBounded(
		nil,
		forward, addedOnly,
		start, end,
		ctracker)
}

func newPreOrderNodeIteratorBounded[E Key, V any](bnds *bounds[E], forward, addedOnly bool, start, end *binTreeNode[E, V], ctracker *changeTracker) subNodeCachingIterator[E, V] {
	var op func(current *binTreeNode[E, V], end *binTreeNode[E, V]) *binTreeNode[E, V]
	if forward {
		op = (*binTreeNode[E, V]).nextPreOrderNode
	} else {
		op = (*binTreeNode[E, V]).previousPreOrderNode
	}

	// do the added-only filter first, because it is simpler
	if addedOnly {
		wrappedOp := op
		op = func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) *binTreeNode[E, V] {
			return currentNode.nextAdded(endNode, wrappedOp)
		}
	}

	if bnds != nil {
		wrappedOp := op
		op = func(currentNode *binTreeNode[E, V], endNode *binTreeNode[E, V]) *binTreeNode[E, V] {
			return currentNode.nextInBounds(endNode, wrappedOp, bnds)
		}
	}

	return newSubNodeCachingIterator(
		bnds,
		forward, addedOnly,
		start, end,
		ctracker,
		op,
		forward,
		forward || addedOnly)
}
