package goip

type singleSegmentsIterator struct {
	original []*AddressDivision
}

func (it *singleSegmentsIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleSegmentsIterator) Next() (res []*AddressDivision) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type multiSegmentsIterator struct {
	done                    bool
	hostSegmentIndex        int
	networkSegmentIndex     int
	nextSet                 []*AddressDivision
	variations              []Iterator[*AddressSegment]
	excludeFunc             func([]*AddressDivision) bool
	segIteratorProducer     func(int) Iterator[*AddressSegment]
	hostSegIteratorProducer func(int) Iterator[*AddressSegment]
}

func (it *multiSegmentsIterator) HasNext() bool {
	return !it.done
}

func (it *multiSegmentsIterator) updateVariations(start int) {
	i := start
	nextSet := it.nextSet
	variations := it.variations
	segIteratorProducer := it.segIteratorProducer

	for ; i < it.hostSegmentIndex; i++ {
		variations[i] = segIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToDiv()
	}

	if i == it.networkSegmentIndex {
		variations[i] = it.hostSegIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToDiv()
	}
}

func (it *multiSegmentsIterator) increment() (res []*AddressDivision) {
	var previousSegs []*AddressDivision
	// the current set of segments already holds the next iteration,
	// this searches for the set of segments to follow.
	variations := it.variations
	nextSet := it.nextSet

	for j := it.networkSegmentIndex; j >= 0; j-- { // for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1)
		for variations[j].HasNext() {
			if previousSegs == nil {
				previousSegs = cloneDivs(nextSet)
			}
			nextSet[j] = variations[j].Next().ToDiv()
			it.updateVariations(j + 1)
			excludeFunc := it.excludeFunc
			if excludeFunc != nil && excludeFunc(nextSet) {
				// try again, starting over
				j = it.networkSegmentIndex
			} else {
				return previousSegs
			}
		}
	}

	it.done = true

	if previousSegs == nil {
		// never found set of candidate segments
		return nextSet
	}
	// found a candidate to follow, but was rejected.
	// nextSet has that rejected candidate,
	// so we must return the set that was created prior to that.
	return previousSegs
}
