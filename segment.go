package goip

const SegIntSize = 32 // must match the bit count of SegInt

// SegInt is an integer type for holding generic address segment values.
// It is at least as large as all address segment values: [IPv6SegInt], [IPv4SegInt], [MACSegInt].
//
// Must be at least uint16 to handle IPv6, at least 32 to handle single-segment IPv4, and no larger than 64 since bits.TrailingZeros64 is used.
// IP address segment code uses bits.TrailingZeros32 and bits.LeadingZeros32, so it cannot be larger than 32.
type SegInt = uint32

type SegIntCount = uint64 // (max value of SegInt) + 1

type segderiver interface {
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues
}

type segmentValues interface {
	// getSegmentValue gets the lower value for a segment
	getSegmentValue() SegInt
	// getUpperSegmentValue gets the upper value for a segment
	getUpperSegmentValue() SegInt
}

type addressSegmentInternal struct {
	addressDivisionInternal
}
