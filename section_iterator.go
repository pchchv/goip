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
