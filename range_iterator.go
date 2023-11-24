package goip

type sequRangeIterator[T SequentialRangeConstraint[T]] struct {
	rng                 *SequentialRange[T]
	creator             func(T, T) *SequentialRange[T]
	prefixBlockIterator Iterator[T]
	prefixLength        BitCount
	notFirst            bool
}
