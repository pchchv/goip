package goip

// getNetworkSegmentIndex returns the index of the segment containing the last byte within the network prefix
// When networkPrefixLength is zero (so there are no segments containing bytes within the network prefix), returns -1
func getNetworkSegmentIndex(networkPrefixLength BitCount, bytesPerSegment int, bitsPerSegment BitCount) int {
	if bytesPerSegment != 1 {
		if bytesPerSegment == 2 {
			return int((networkPrefixLength - 1) >> ipv6BitsToSegmentBitshift) // note this is intentionally a signed shift and not >>> so that networkPrefixLength of 0 returns -1
		}
		return int((networkPrefixLength - 1) / bitsPerSegment)
	}
	return int((networkPrefixLength - 1) >> ipv4BitsToSegmentBitshift)
}

// getHostSegmentIndex returns the index of the segment containing the first byte outside the network prefix.
// When networkPrefixLength is nil, or it matches or exceeds the bit length, returns the segment count.
func getHostSegmentIndex(networkPrefixLength BitCount, bytesPerSegment int, bitsPerSegment BitCount) int {
	if bytesPerSegment != 1 {
		if bytesPerSegment == 2 {
			return int(networkPrefixLength >> ipv6BitsToSegmentBitshift)
		}
		return int(networkPrefixLength / bitsPerSegment)
	}
	return int(networkPrefixLength >> ipv4BitsToSegmentBitshift)
}
