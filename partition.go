package goip

import "math/big"

// Partition is a collection of items (such as addresses)
// partitioned from an original item (such as a subnet).
// Much like an iterator,
// the elements of a partition can be iterated just once (using the iterator,
// using ForEach, or using any other iteration),
// after which it becomes empty.
type Partition[T any] struct {
	single    T
	original  T
	hasSingle bool
	iterator  Iterator[T]
	count     *big.Int
}
