package goip

import "github.com/pchchv/goip/tree"

type Cached = tree.C

// addressKeyIterator implements the address key iterator for tries.
type addressKeyIterator[T TrieKeyConstraint[T]] struct {
	tree.TrieKeyIterator[trieKey[T]]
}

func (iter addressKeyIterator[T]) Next() (t T) {
	return iter.TrieKeyIterator.Next().address
}

func (iter addressKeyIterator[T]) Remove() (t T) {
	return iter.TrieKeyIterator.Remove().address
}

type addressTrieNodeIteratorRem[T TrieKeyConstraint[T], V any] struct {
	tree.TrieNodeIteratorRem[trieKey[T], V]
}

func (iter addressTrieNodeIteratorRem[T, V]) Next() *TrieNode[T] {
	return toAddressTrieNode[T](iter.TrieNodeIteratorRem.Next())
}

func (iter addressTrieNodeIteratorRem[T, V]) Remove() *TrieNode[T] {
	return toAddressTrieNode[T](iter.TrieNodeIteratorRem.Remove())
}

type addressTrieNodeIterator[T TrieKeyConstraint[T], V any] struct {
	tree.TrieNodeIterator[trieKey[T], V]
}

func (iter addressTrieNodeIterator[T, V]) Next() *TrieNode[T] {
	return toAddressTrieNode[T](iter.TrieNodeIterator.Next())
}

type cachingAddressTrieNodeIterator[T TrieKeyConstraint[T], V any] struct {
	tree.CachingTrieNodeIterator[trieKey[T], V]
}

func (iter cachingAddressTrieNodeIterator[T, V]) Next() *TrieNode[T] {
	return toAddressTrieNode[T](iter.CachingTrieNodeIterator.Next())
}

func (iter cachingAddressTrieNodeIterator[T, V]) Remove() *TrieNode[T] {
	return toAddressTrieNode[T](iter.CachingTrieNodeIterator.Remove())
}

// CachingTrieIterator is an iterator of a tree that allows you to cache an object with the
// lower or upper sub-node of the currently visited node.
// The cached object can be retrieved later when iterating the sub-node.
// That allows you to provide iteration context from a parent to its sub-nodes when iterating,
// but can only be provided with iterators in which parent nodes are visited before their sub-nodes.
// The caching and retrieval is done in constant-time.
type CachingTrieIterator[T any] interface {
	IteratorWithRemove[T]
	// Note: We could theoretically try to make the cached type generic.
	// But the problem with that is that the iterator methods that return them cannot be generic on their own, the whole type would need to specify the cache type.
	// The other problem is that even if we could, some callers would not care about the caching behaviour and thus would not want to have to specify a cache type.
	//
	// GetCached returns an object previously cached with the current iterated node.
	// After Next has returned a node,
	// if an object was cached by a call to CacheWithLowerSubNode or CacheWithUpperSubNode
	// was called when that node's parent was previously returned by Next,
	// then this returns that cached object.
	GetCached() Cached
	// CacheWithLowerSubNode caches an object with the lower sub-node of the current iterated node.
	// After Next has returned a node,
	// calling this method caches the provided object with the lower sub-node so that it can
	// be retrieved with GetCached when the lower sub-node is visited later.
	//
	// Returns false if it could not be cached, either because the node has since been removed with a call to Remove,
	// because Next has not been called yet, or because there is no lower sub node for the node previously returned by  Next.
	//
	// The caching and retrieval is done in constant time.
	CacheWithLowerSubNode(Cached) bool
	// CacheWithUpperSubNode caches an object with the upper sub-node of the current iterated node.
	// After Next has returned a node,
	// calling this method caches the provided object with the upper sub-node so that it can
	// be retrieved with GetCached when the upper sub-node is visited later.
	//
	// Returns false if it could not be cached, either because the node has since been removed with a call to Remove,
	// because Next has not been called yet, or because there is no upper sub node for the node previously returned by Next.
	//
	// The caching and retrieval is done in constant time.
	CacheWithUpperSubNode(Cached) bool
}

type emptyIterator[T any] struct{}

func (it emptyIterator[T]) HasNext() bool {
	return false
}

func (it emptyIterator[T]) Next() (t T) {
	return
}

type cachingAssociativeAddressTrieNodeIteratorX[T TrieKeyConstraint[T], V any] struct {
	tree.CachingTrieNodeIterator[trieKey[T], V]
}

func (iter cachingAssociativeAddressTrieNodeIteratorX[T, V]) Next() *AssociativeTrieNode[T, V] {
	return toAssociativeTrieNode[T, V](iter.CachingTrieNodeIterator.Next())
}

func (iter cachingAssociativeAddressTrieNodeIteratorX[T, V]) Remove() *AssociativeTrieNode[T, V] {
	return toAssociativeTrieNode[T, V](iter.CachingTrieNodeIterator.Remove())
}

type associativeAddressTrieNodeIteratorRem[T TrieKeyConstraint[T], V any] struct {
	tree.TrieNodeIteratorRem[trieKey[T], V]
}

func (iter associativeAddressTrieNodeIteratorRem[T, V]) Next() *AssociativeTrieNode[T, V] {
	return toAssociativeTrieNode[T, V](iter.TrieNodeIteratorRem.Next())
}

func (iter associativeAddressTrieNodeIteratorRem[T, V]) Remove() *AssociativeTrieNode[T, V] {
	return toAssociativeTrieNode[T, V](iter.TrieNodeIteratorRem.Remove())
}

type associativeAddressTrieNodeIterator[T TrieKeyConstraint[T], V any] struct {
	tree.TrieNodeIterator[trieKey[T], V]
}

func (iter associativeAddressTrieNodeIterator[T, V]) Next() *AssociativeTrieNode[T, V] {
	return toAssociativeTrieNode[T, V](iter.TrieNodeIterator.Next())
}

func nilAddressIterator[T any]() Iterator[T] {
	return emptyIterator[T]{}
}
