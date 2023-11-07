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
