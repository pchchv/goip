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
