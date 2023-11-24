package goip

import "math/big"

var (
	_ SpanPartitionConstraint[*IPAddress]
	_ SpanPartitionConstraint[*IPv4Address]
	_ SpanPartitionConstraint[*IPv6Address]
	_ SpanPartitionConstraint[*IPAddressSection]
	_ SpanPartitionConstraint[*IPv4AddressSection]
	_ SpanPartitionConstraint[*IPv6AddressSection]

	_ IteratePartitionConstraint[*Address]
	_ IteratePartitionConstraint[*IPAddress]
	_ IteratePartitionConstraint[*IPv4Address]
	_ IteratePartitionConstraint[*IPv6Address]
	_ IteratePartitionConstraint[*MACAddress]
	_ IteratePartitionConstraint[*IPAddressSection]
	_ IteratePartitionConstraint[*IPv4AddressSection]
	_ IteratePartitionConstraint[*IPv6AddressSection]
	_ IteratePartitionConstraint[*MACAddressSection]

	_ MappedPartition[*Address, any]     = ApplyForEach[*Address, any](nil, nil)
	_ MappedPartition[*IPAddress, any]   = ApplyForEach[*IPAddress, any](nil, nil)
	_ MappedPartition[*IPv4Address, any] = ApplyForEach[*IPv4Address, any](nil, nil)
	_ MappedPartition[*IPv6Address, any] = ApplyForEach[*IPv6Address, any](nil, nil)
	_ MappedPartition[*MACAddress, any]  = ApplyForEach[*MACAddress, any](nil, nil)
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

// IteratePartitionConstraint is the generic type constraint for IP subnet and IP section iteration partitions.
type IteratePartitionConstraint[T any] interface {
	AddressDivisionSeries
	PrefixedConstraint[T]
	AssignMinPrefixForBlock() T
	PrefixBlockIterator() Iterator[T]
	Iterator() Iterator[T]
}

// ApplyForEachConditionally supplies to the given function each element of the given partition,
// inserting return values into the returned map as directed.  When the action returns true as the second return value,
// then the other return value is added to the map.
func ApplyForEachConditionally[T GenericKeyConstraint[T], V any](part *Partition[T], action func(T) (V, bool)) MappedPartition[T, V] {
	results := make(map[Key[T]]V)
	if action != nil && part != nil {
		part.ForEach(func(addr T) {
			if result, ok := action(addr); ok {
				results[addr.ToGenericKey()] = result
			}
		})
	}
	return results
}

// ApplyForEach supplies to the given function each element of the given partition,
// inserting return values into the returned map.
func ApplyForEach[T GenericKeyConstraint[T], V any](part *Partition[T], action func(T) V) MappedPartition[T, V] {
	results := make(map[Key[T]]V)
	if action != nil && part != nil {
		part.ForEach(func(addr T) {
			results[addr.ToGenericKey()] = action(addr)
		})
	}
	return results
}

// PartitionWithSpanningBlocks partitions the address series into prefix blocks and single addresses.
//
// This method iterates through a list of prefix blocks of different sizes that span the entire subnet.
func PartitionWithSpanningBlocks[T SpanPartitionConstraint[T]](newAddr T) *Partition[T] {
	if !newAddr.IsMultiple() {
		if !newAddr.IsPrefixed() {
			return &Partition[T]{
				original:  newAddr,
				single:    newAddr,
				hasSingle: true,
				count:     bigOneConst(),
			}
		}
		return &Partition[T]{
			original:  newAddr,
			single:    newAddr.WithoutPrefixLen(),
			hasSingle: true,
			count:     bigOneConst(),
		}
	} else if newAddr.IsSinglePrefixBlock() {
		return &Partition[T]{
			original:  newAddr,
			single:    newAddr,
			hasSingle: true,
			count:     bigOneConst(),
		}
	}

	blocks := newAddr.SpanWithPrefixBlocks()
	return &Partition[T]{
		original: newAddr,
		iterator: &sliceIterator[T]{blocks},
		count:    big.NewInt(int64(len(blocks))),
	}
}

// PartitionWithSingleBlockSize partitions the address series into prefix blocks and single addresses.
//
// This method chooses the maximum block size for a list of prefix blocks contained by the address or subnet,
// and then iterates to produce blocks of that size.
func PartitionWithSingleBlockSize[T IteratePartitionConstraint[T]](newAddr T) *Partition[T] {
	if !newAddr.IsMultiple() {
		if !newAddr.IsPrefixed() {
			return &Partition[T]{
				original:  newAddr,
				single:    newAddr,
				hasSingle: true,
				count:     bigOneConst(),
			}
		}
		return &Partition[T]{
			original:  newAddr,
			single:    newAddr.WithoutPrefixLen(),
			hasSingle: true,
			count:     bigOneConst(),
		}
	} else if newAddr.IsSinglePrefixBlock() {
		return &Partition[T]{
			original:  newAddr,
			single:    newAddr,
			hasSingle: true,
			count:     bigOneConst(),
		}
	}

	// prefix blocks are handled as prefix blocks,
	// such as 1.2.*.*, which is handled as prefix block iterator for 1.2.0.0/16,
	// but 1.2.3-4.5 is handled as iterator with no prefix lengths involved
	series := newAddr.AssignMinPrefixForBlock()
	if series.GetPrefixLen().bitCount() != newAddr.GetBitCount() {
		return &Partition[T]{
			original: newAddr,
			iterator: series.PrefixBlockIterator(),
			count:    series.GetPrefixCountLen(series.GetPrefixLen().bitCount()),
		}
	}

	return &Partition[T]{
		original: newAddr,
		iterator: newAddr.WithoutPrefixLen().Iterator(),
		count:    newAddr.GetCount(),
	}
}
