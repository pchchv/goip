package tree

type binTree[E Key, V any] struct {
	root *binTreeNode[E, V]
}

// GetRoot returns the root node of this trie,
// which can be nil for a zero-valued uninitialized trie,
// but not for any other trie
func (tree *binTree[E, V]) GetRoot() *binTreeNode[E, V] {
	return tree.root
}

// Size returns the number of elements in the tree.
// Only nodes for which IsAdded() returns true are counted.
// When zero is returned, IsEmpty() returns true.
func (tree *binTree[E, V]) Size() int {
	if tree == nil {
		return 0
	}
	return tree.GetRoot().Size()
}

// NodeSize returns the number of nodes in the tree,
// which is always more than the number of elements.
func (tree *binTree[E, V]) NodeSize() int {
	if tree == nil {
		return 0
	}
	return tree.GetRoot().NodeSize()
}
