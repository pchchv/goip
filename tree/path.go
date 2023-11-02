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
