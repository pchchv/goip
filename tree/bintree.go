package tree

import (
	"fmt"
	"strings"
)

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

// String returns a visual representation of the tree with one node per line.
func (tree *binTree[E, V]) String() string {
	return tree.TreeString(true)
}

func (tree binTree[E, V]) format(state fmt.State, verb rune) {
	switch verb {
	case 's', 'v':
		_, _ = state.Write([]byte(tree.String()))
		return
	}
	// In default fmt handling (see printValue), we write all the fields of each struct inside curlies {}
	// When a pointer is encountered, the pointer is printed unless the nesting depth is 0
	// How that pointer is printed varies a lot depending on the verb and flags.
	// So, in the case of unsupported flags, let's print { rootPointer } where rootPointer is printed according to the flags and verb.
	s := flagsFromState(state, verb)
	rootStr := fmt.Sprintf(s, binTreeNodePtr[E, V](tree.root))
	bytes := make([]byte, len(rootStr)+2)
	bytes[0] = '{'
	shifted := bytes[1:]
	copy(shifted, rootStr)
	shifted[len(rootStr)] = '}'
	_, _ = state.Write(bytes)
}

func (tree *binTree[E, V]) printTree(builder *strings.Builder, inds indents, withNonAddedKeys bool) {
	if tree == nil {
		builder.WriteString(inds.nodeIndent)
		builder.WriteString(nilString())
		builder.WriteByte('\n')
	} else {
		tree.GetRoot().printTree(builder, inds, withNonAddedKeys, true)
	}
}
