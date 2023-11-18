package goip

import "math/bits"

func coverWithPrefixBlockWrapped(lower, upper ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	return []ExtendedIPSegmentSeries{coverWithPrefixBlock(lower, upper)}
}

func coverWithPrefixBlock(lower, upper ExtendedIPSegmentSeries) ExtendedIPSegmentSeries {
	var currentSegment int
	var previousSegmentBits BitCount
	segCount := lower.GetSegmentCount()
	bitsPerSegment := lower.GetBitsPerSegment()
	for ; currentSegment < segCount; currentSegment++ {
		lowerSeg := lower.GetGenericSegment(currentSegment)
		upperSeg := upper.GetGenericSegment(currentSegment)
		var lowerValue, upperValue SegInt
		lowerValue = lowerSeg.GetSegmentValue() // these are single addresses, so lower or upper value no different here
		upperValue = upperSeg.GetSegmentValue()
		differing := lowerValue ^ upperValue
		if differing != 0 {
			highestDifferingBitInRange := BitCount(bits.LeadingZeros32(differing)) - (SegIntSize - bitsPerSegment)
			differingBitPrefixLen := highestDifferingBitInRange + previousSegmentBits
			return lower.ToPrefixBlockLen(differingBitPrefixLen)
		}
		previousSegmentBits += bitsPerSegment
	}
	// all bits match, it's just a single address
	return lower.ToPrefixBlockLen(lower.GetBitCount())
}
