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

func (it *segmentIterator) HasNext() bool {
	return !it.done
}

func (it *segmentIterator) Next() (res *AddressSegment) {
	if it.HasNext() {
		cur := it.current
		res = createAddressSegment(
			it.creator.deriveNewSeg(
				cur,
				it.segmentPrefixLength))
		cur++
		if cur > it.last {
			it.done = true
		} else {
			it.current = cur
		}
	}
	return
}

type segmentPrefBlockIterator struct {
	segmentIterator
	upperShiftMask  SegInt
	shiftAdjustment BitCount
}

func (it *segmentPrefBlockIterator) Next() (res *AddressSegment) {
	if it.HasNext() {
		cur := it.current
		blockLow := cur << uint(it.shiftAdjustment)
		res = createAddressSegment(
			it.creator.deriveNewMultiSeg(
				blockLow,
				blockLow|it.upperShiftMask,
				it.segmentPrefixLength))
		cur++
		if cur > it.last {
			it.done = true
		} else {
			it.current = cur
		}
	}
	return
}

type segmentPrefIterator struct {
	segmentPrefBlockIterator
	originalLower SegInt
	originalUpper SegInt
	notFirst      bool
}
