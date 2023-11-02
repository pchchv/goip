package tree

import (
	"strconv"
	"strings"
)

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

// ListString returns a visual representation of the sub-list with this node as root,
// with one node per line.
//
// withNonAddedKeys: whether to show nodes that are not added nodes
// withSizes: whether to include the counts of added nodes in each sub-list
func (node *PathNode[E, V]) ListString(withNonAddedKeys, withSizes bool) string {
	builder := strings.Builder{}
	builder.WriteByte('\n')
	node.printList(&builder, indents{}, withNonAddedKeys, withSizes)
	return builder.String()
}

func (node *PathNode[E, V]) printList(builder *strings.Builder,
	indents indents,
	withNonAdded,
	withSizes bool) {
	if node == nil {
		builder.WriteString(indents.nodeIndent)
		builder.WriteString(nilString())
		builder.WriteByte('\n')
		return
	}

	next := node
	for {
		if withNonAdded || next.IsAdded() {
			builder.WriteString(indents.nodeIndent)
			builder.WriteString(next.String())
			if withSizes {
				builder.WriteString(" (")
				builder.WriteString(strconv.Itoa(next.Size()))
				builder.WriteByte(')')
			}
			builder.WriteByte('\n')
		} else {
			builder.WriteString(indents.nodeIndent)
			builder.WriteString(nonAddedNodeCircle)
			builder.WriteByte('\n')
		}
		indents.nodeIndent = indents.subNodeInd + rightElbow
		indents.subNodeInd = indents.subNodeInd + belowElbows
		if next = next.next; next == nil {
			break
		}
	}
}

// Path is a list of nodes derived from following a path in a tree.
// Each node in the list corresponds to a node in the tree.
// Each node in the list corresponds to a tree node that is
// a direct or indirect sub-node of the tree node corresponding to the previous node in the list.
// Not all nodes in the pathway through the tree need to be included in the linked list.
//
// In other words, a path follows a pathway through a tree from root to leaf,
// but not necessarily including all nodes encountered along the way.
type Path[E Key, V any] struct {
	root *PathNode[E, V]
	leaf *PathNode[E, V]
}

// GetRoot returns the beginning of the Path,
// which may or may not match the tree root of the originating tree.
func (path *Path[E, V]) GetRoot() *PathNode[E, V] {
	return path.root
}

// GetLeaf returns the end of the Path,
// which may or may not match a leaf in the originating tree.
func (path *Path[E, V]) GetLeaf() *PathNode[E, V] {
	return path.leaf
}
