package goip

type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

// GetSegmentPrefixLen returns the network prefix for the segment.
// For an address like "1.2.0.0.0/16", the network prefix is 16.
// When it comes to each address division or segment,
// the prefix for the division is the prefix obtained by applying the address or section prefix.
//
// For example, the address is "1.2.0.0.0/20."
// The first segment has no prefix because the address prefix 20 extends beyond
// the 8 bits of the first segment and is not even applied to it.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which lie in the second segment, it does not apply to that segment either.
// The third segment has a prefix of 4 because
// the address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network section of the address or segment.
// The last segment is prefixed with 0 because not
// a single bit of the network section of the address or segment.
//
// Division prefixes applied throughout the address: nil ... nil (1 to the segment bit length) 0 ... 0.
//
// If the segment has no prefix, nil is returned.
func (seg *ipAddressSegmentInternal) GetSegmentPrefixLen() PrefixLen {
	return seg.getDivisionPrefixLength()
}
