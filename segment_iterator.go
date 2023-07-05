package goip

type singleSegmentIterator struct {
	original *AddressSegment
}

func (it *singleSegmentIterator) HasNext() bool {
	return it.original != nil
}

func (it *singleSegmentIterator) Next() (res *AddressSegment) {
	if it.HasNext() {
		res = it.original.toAddressSegment()
		it.original = nil
	}
	return
}

type segmentIterator struct {
	done                bool
	current             SegInt
	last                SegInt
	creator             segderiver
	segmentPrefixLength PrefixLen
}
