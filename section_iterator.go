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
