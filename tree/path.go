package tree

// PathNode is an element in the list of a Path
type PathNode[E Key, V any] struct {
	previous   *PathNode[E, V]
	next       *PathNode[E, V]
	added      bool
	item       E   // the key for the node
	value      V   // only for associative trie nodes
	storedSize int // the number of added nodes below this one, including this one if added
}

// Next returns the next node in the path.
func (node *PathNode[E, V]) Next() *PathNode[E, V] {
	return node.next
}

// Previous returns the previous node in the path.
func (node *PathNode[E, V]) Previous() *PathNode[E, V] {
	return node.previous
}

// GetKey gets the key used for placing the node in the tree.
func (node *PathNode[E, V]) GetKey() (key E) {
	if node != nil {
		return node.item
	}
	return
}

// GetValue returns the value assigned to the node
func (node *PathNode[E, V]) GetValue() (val V) {
	if node != nil {
		val = node.value
	}
	return
}

// IsAdded returns whether the node was "added".
// Some binary tree nodes are considered "added" and others are not.
// Those nodes created for key elements added to the tree are "added" nodes.
// Those that are not added are those nodes created to serve as junctions for the added nodes.
// Only added elements contribute to the size of a tree.
// When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
// which is when an added node has less than two added sub-nodes.
func (node *PathNode[E, V]) IsAdded() bool {
	return node != nil && node.added
}

// Size returns the count of nodes added to
// the sub-tree starting from this node as root and moving downwards to sub-nodes.
// This is a constant-time operation since the size is maintained in each node.
func (node *PathNode[E, V]) Size() (storedSize int) {
	if node != nil {
		storedSize = node.storedSize
		if storedSize == sizeUnknown {
			prev, next := node, node.next
			for ; next != nil && next.storedSize == sizeUnknown; prev, next = next, next.next {
			}
			var nodeSize int
			for {
				if prev.IsAdded() {
					nodeSize++
				}
				if next != nil {
					nodeSize += next.storedSize
				}
				prev.storedSize = nodeSize
				if prev == node {
					break
				}
				prev = node.previous
			}
			storedSize = node.storedSize
		}
	}
	return
}

// Returns a visual representation of this node including the key,
// with an open circle indicating this node is not an added node,
// a closed circle indicating this node is an added node.
func (node *PathNode[E, V]) String() string {
	if node == nil {
		return NodeString[E, V](nil)
	}
	return NodeString[E, V](node)
}
