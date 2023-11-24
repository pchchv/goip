package goip

import "math/big"

var (
	_ SpanPartitionConstraint[*IPAddress]
	_ SpanPartitionConstraint[*IPv4Address]
	_ SpanPartitionConstraint[*IPv6Address]
	_ SpanPartitionConstraint[*IPAddressSection]
	_ SpanPartitionConstraint[*IPv4AddressSection]
	_ SpanPartitionConstraint[*IPv6AddressSection]
)

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

func (part *Partition[T]) predicateForEach(predicate func(T) bool, returnEarly bool) bool {
	if part.iterator == nil {
		return predicate(part.single)
	}

	result := true
	iterator := part.iterator
	for iterator.HasNext() {
		if !predicate(iterator.Next()) {
			result = false
			if returnEarly {
				break
			}
		}
	}
	return result
}

// PredicateForEach applies the supplied predicate operation to each element of the partition,
// returning true if they all return true, false otherwise
func (part *Partition[T]) PredicateForEach(predicate func(T) bool) bool {
	return part.predicateForEach(predicate, false)
}

func (part *Partition[T]) predicateForAny(predicate func(address T) bool, returnEarly bool) bool {
	return !part.predicateForEach(func(addr T) bool {
		return !predicate(addr)
	}, returnEarly)
}

// PredicateForAny applies the supplied predicate operation to each element of the partition,
// returning true if the given predicate returns true for any of the elements.
func (part *Partition[T]) PredicateForAny(predicate func(T) bool) bool {
	return part.predicateForAny(predicate, false)
}

// PredicateForEachEarly applies the supplied predicate operation to each element of the partition,
// returning false if the given predicate returns false for any of the elements.
//
// The method returns when one application of the predicate returns false (determining the overall result)
func (part *Partition[T]) PredicateForEachEarly(predicate func(T) bool) bool {
	return part.predicateForEach(predicate, false)
}

// PredicateForAnyEarly applies the supplied predicate operation to each element of the partition,
// returning true if the given predicate returns true for any of the elements.
//
// The method returns when one application of the predicate returns true (determining the overall result)
func (part *Partition[T]) PredicateForAnyEarly(predicate func(T) bool) bool {
	return part.predicateForAny(predicate, true)
}

// SpanPartitionConstraint is the generic type constraint for IP subnet spanning partitions.
type SpanPartitionConstraint[T any] interface {
	AddressDivisionSeries
	PrefixedConstraint[T]
	SpanWithPrefixBlocks() []T
}
