package goip

// PrefixBlockConstraint is the generic type constraint used for a prefix block allocator.
type PrefixBlockConstraint[T any] interface {
	SequentialRangeConstraint[T]
	MergeToPrefixBlocks(...T) []T
	PrefixBlockIterator() Iterator[T]
}
