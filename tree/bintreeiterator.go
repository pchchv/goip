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
