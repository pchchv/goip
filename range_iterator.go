package goip

type sequRangeIterator[T SequentialRangeConstraint[T]] struct {
	rng                 *SequentialRange[T]
	creator             func(T, T) *SequentialRange[T]
	prefixBlockIterator Iterator[T]
	prefixLength        BitCount
	notFirst            bool
}

func (it *sequRangeIterator[T]) HasNext() bool {
	return it.prefixBlockIterator.HasNext()
}

func (it *sequRangeIterator[T]) Next() (res *SequentialRange[T]) {
	if it.HasNext() {
		next := it.prefixBlockIterator.Next()
		if !it.notFirst {
			it.notFirst = true
			// next is a prefix block
			lower := it.rng.GetLower()
			prefLen := it.prefixLength
			if it.HasNext() {
				if !lower.IncludesZeroHostLen(prefLen) {
					return it.creator(lower, next.GetUpper())
				}
			} else {
				upper := it.rng.GetUpper()
				if !lower.IncludesZeroHostLen(prefLen) || !upper.IncludesMaxHostLen(prefLen) {
					return it.creator(lower, upper)
				}
			}
		} else if !it.HasNext() {
			upper := it.rng.GetUpper()
			if !upper.IncludesMaxHostLen(it.prefixLength) {
				return it.creator(next.GetLower(), upper)
			}
		}
		lower, upper := next.getLowestHighestAddrs()
		return newSequRangeUnchecked(lower, upper, lower != upper)
	}
	return
}
