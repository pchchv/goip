package tree

type binTree[E Key, V any] struct {
	root *binTreeNode[E, V]
}
