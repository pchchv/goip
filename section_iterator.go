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

func (it *multiSegmentsIterator) init() {
	it.updateVariations(0)
	nextSet := it.nextSet
	variations := it.variations
	divCount := len(variations)
	hostSegIteratorProducer := it.hostSegIteratorProducer

	for i := it.networkSegmentIndex + 1; i < divCount; i++ {
		variations[i] = hostSegIteratorProducer(i)
		nextSet[i] = variations[i].Next().ToDiv()
	}

	excludeFunc := it.excludeFunc
	if excludeFunc != nil && excludeFunc(it.nextSet) {
		it.increment()
	}
}

func (it *multiSegmentsIterator) Next() (res []*AddressDivision) {
	if it.HasNext() {
		res = it.increment()
	}
	return
}

type singleSectionIterator struct {
	original *AddressSection
}

func (it *singleSectionIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleSectionIterator) Next() (res *AddressSection) {
	if it.HasNext() {
		res = it.original
		it.original = nil
	}
	return
}

type multiSectionIterator struct {
	original        *AddressSection
	iterator        Iterator[[]*AddressDivision]
	valsAreMultiple bool
	prefixLen       PrefixLen
}

func (it *multiSectionIterator) HasNext() bool {
	return it.iterator.HasNext()
}

func (it *multiSectionIterator) Next() (res *AddressSection) {
	if it.HasNext() {
		segs := it.iterator.Next()
		original := it.original
		res = createSection(segs, it.prefixLen, original.addrType)
		res.isMult = it.valsAreMultiple
	}
	return
}

type prefixSectionIterator struct {
	original   *AddressSection
	iterator   Iterator[[]*AddressDivision]
	isNotFirst bool
	prefixLen  PrefixLen
}

func (it *prefixSectionIterator) HasNext() bool {
	return it.iterator.HasNext()
}

func (it *prefixSectionIterator) Next() (res *AddressSection) {
	if it.HasNext() {
		segs := it.iterator.Next()
		original := it.original
		res = createSection(segs, it.prefixLen, original.addrType)
		if !it.isNotFirst {
			res.initMultiple() // sets isMultiple
			it.isNotFirst = true
		} else if !it.HasNext() {
			res.initMultiple() // sets isMultiple
		} else {
			res.isMult = true
		}
	}
	return
}
