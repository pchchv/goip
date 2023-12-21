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

func (it *segmentPrefIterator) Next() (res *AddressSegment) {
	if it.HasNext() {
		var low, high SegInt
		cur := it.current
		blockLow := cur << uint(it.shiftAdjustment)
		blockHigh := blockLow | it.upperShiftMask
		cur++
		it.current = cur
		if it.notFirst {
			low = blockLow
		} else {
			low = it.originalLower
			it.notFirst = true
		}

		if cur <= it.last {
			high = blockHigh
		} else {
			high = it.originalUpper
			it.done = true
		}
		res = createAddressSegment(
			it.creator.deriveNewMultiSeg(
				low,
				high,
				it.segmentPrefixLength))
	}
	return
}

type macSegmentIterator struct {
	Iterator[*AddressSegment]
}

func (iter macSegmentIterator) Next() *MACAddressSegment {
	return iter.Iterator.Next().ToMAC()
}

type ipv4SegmentIterator struct {
	Iterator[*AddressSegment]
}

func (iter ipv4SegmentIterator) Next() *IPv4AddressSegment {
	return iter.Iterator.Next().ToIPv4()
}

type ipSegmentIterator struct {
	Iterator[*AddressSegment]
}

func (iter ipSegmentIterator) Next() *IPAddressSegment {
	return iter.Iterator.Next().ToIP()
}

// wrappedSegmentIterator converts an IP address segment iterator to an address segment iterator
type wrappedSegmentIterator[T AddressSegmentType] struct {
	Iterator[T]
}

func (iter wrappedSegmentIterator[T]) Next() *AddressSegment {
	return iter.Iterator.Next().ToSegmentBase()
}

type ipv6SegmentIterator struct {
	Iterator[*AddressSegment]
}

func (iter ipv6SegmentIterator) Next() *IPv6AddressSegment {
	return iter.Iterator.Next().ToIPv6()
}

func segIterator(
	original *addressSegmentInternal,
	originalLower,
	originalUpper SegInt,
	bitCount BitCount,
	creator segderiver,
	segmentPrefixLength PrefixLen,
	isPrefixIterator, isBlockIterator bool) Iterator[*AddressSegment] {
	var shiftAdjustment BitCount
	var shiftMask, upperShiftMask SegInt
	if segmentPrefixLength == nil {
		isPrefixIterator = false // prefixBlockIterator() in which seg has no prefix
		isBlockIterator = false
	}

	if isPrefixIterator {
		prefLen := segmentPrefixLength.bitCount()
		prefLen = checkBitCount(bitCount, prefLen)
		shiftAdjustment = bitCount - prefLen
		shiftMask = ^SegInt(0) << uint(shiftAdjustment)
		upperShiftMask = ^shiftMask
	}

	if original != nil && !original.isMultiple() {
		seg := original.toAddressSegment()
		if isBlockIterator {
			seg = createAddressSegment(
				creator.deriveNewMultiSeg(
					originalLower&shiftMask,
					originalUpper|upperShiftMask,
					segmentPrefixLength))
		}
		return &singleSegmentIterator{original: seg}
	}

	if isPrefixIterator {
		current := originalLower >> uint(shiftAdjustment)
		last := originalUpper >> uint(shiftAdjustment)
		segIterator := segmentIterator{
			current:             current,
			last:                last,
			creator:             creator,
			segmentPrefixLength: segmentPrefixLength,
		}
		prefBlockIterator := segmentPrefBlockIterator{
			segmentIterator: segIterator,
			upperShiftMask:  upperShiftMask,
			shiftAdjustment: shiftAdjustment,
		}

		if isBlockIterator {
			return &prefBlockIterator
		}
		return &segmentPrefIterator{
			segmentPrefBlockIterator: prefBlockIterator,
			originalLower:            originalLower,
			originalUpper:            originalUpper,
		}
	}
	return &segmentIterator{
		current:             originalLower,
		last:                originalUpper,
		creator:             creator,
		segmentPrefixLength: segmentPrefixLength,
	}
}

func nilSegIterator() Iterator[*AddressSegment] {
	return &singleSegmentIterator{}
}
