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
