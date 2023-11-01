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

// Clear removes all added nodes from the tree,
// after which IsEmpty() will return true
func (tree *binTree[E, V]) Clear() {
	if root := tree.GetRoot(); root != nil {
		root.Clear()
	}
}

// IsEmpty returns true if there are not any added nodes within this tree
func (tree *binTree[E, V]) IsEmpty() bool {
	return tree.Size() == 0
}

// TreeString returns a visual representation of the tree with one node per line,
// with or without the non-added keys.
func (tree *binTree[E, V]) TreeString(withNonAddedKeys bool) string {
	return tree.GetRoot().TreeString(withNonAddedKeys, true)
}
