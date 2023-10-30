package tree

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
