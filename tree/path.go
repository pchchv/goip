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
