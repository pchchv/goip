package goip

type DelimitedAddressString string

func isDelimitedBoundary(c byte) bool {
	return c == IPv4SegmentSeparator ||
		c == IPv6SegmentSeparator ||
		c == RangeSeparator ||
		c == MacDashedSegmentRangeSeparator
}
