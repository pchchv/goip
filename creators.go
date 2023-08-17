package goip

type addressSegmentCreator interface {
	createRangeSegment(lower, upper SegInt) *AddressDivision
	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	createSegmentInternal(
		value SegInt,
		segmentPrefixLength PrefixLen,
		addressStr string,
		originalVal SegInt,
		isStandardString bool,
		lowerStringStartIndex,
		lowerStringEndIndex int) *AddressDivision
	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision
	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	getMaxValuePerSegment() SegInt
}
