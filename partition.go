package goip

import "math/big"

// MappedPartition is a mapping from the address types in a [Partition] to values of a generic type V.
type MappedPartition[T GenericKeyConstraint[T], V any] map[Key[T]]V

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

// ForEach calls the given action on each partition element.
func (part *Partition[T]) ForEach(action func(T)) {
	if part.iterator == nil {
		if part.hasSingle {
			part.hasSingle = false
			action(part.single)
		}
	} else {
		iterator := part.iterator
		for iterator.HasNext() {
			action(iterator.Next())
		}
		part.iterator = nil
	}
}

// Iterator provides an iterator to iterate through each element of the partition.
func (part *Partition[T]) Iterator() Iterator[T] {
	if part.iterator == nil {
		if part.hasSingle {
			part.hasSingle = false
			res := &singleIterator[T]{original: part.single}
			return res
		}
		return nil
	}

	res := part.iterator
	part.iterator = nil
	return res
}
