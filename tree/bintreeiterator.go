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
