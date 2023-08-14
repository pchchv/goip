package goip

type subnetOption int

const (
	zerosOnly = subnetOption(iota)
	fullRangeOnly
	zerosToFullRange
	zerosOrFullRange
)

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

// Across an address prefixes are:
// IPv6: (nil):...:(nil):(1 to 16):(0):...:(0)
// or IPv4: ...(nil).(1 to 8).(0)...
func getDivisionPrefixLength(divisionBits, divisionPrefixedBits BitCount) PrefixLen {
	if divisionPrefixedBits <= 0 {
		return cacheBitCount(0) // none of the bits in this segment matter
	} else if divisionPrefixedBits <= divisionBits {
		return cacheBitCount(divisionPrefixedBits) // some of the bits in this segment matter
	}
	return nil // all the bits in this segment matter
}

func getPrefixedSegmentPrefixLength(bitsPerSegment BitCount, prefixLength BitCount, segmentIndex int) PrefixLen {
	var decrement int

	if bitsPerSegment == 8 {
		decrement = segmentIndex << ipv4BitsToSegmentBitshift
	} else if bitsPerSegment == 16 {
		decrement = segmentIndex << ipv6BitsToSegmentBitshift
	} else {
		decrement = segmentIndex * int(bitsPerSegment)
	}

	return getDivisionPrefixLength(bitsPerSegment, prefixLength-BitCount(decrement))
}

// Across an address prefixes are:
// IPv6: (nil):...:(nil):(1 to 16):(0):...:(0)
// or IPv4: ...(nil).(1 to 8).(0)...
func getSegmentPrefixLength(bitsPerSegment BitCount, prefixLength PrefixLen, segmentIndex int) PrefixLen {
	if prefixLength != nil {
		return getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength.bitCount(), segmentIndex)
	}
	return nil
}

func getAdjustedPrefixLength(bitsPerSegment BitCount, prefixLength BitCount, fromIndex, endIndex int) PrefixLen {
	var (
		decrement int
		totalBits int
	)

	if bitsPerSegment == 8 {
		decrement = fromIndex << ipv4BitsToSegmentBitshift
		totalBits = endIndex << ipv4BitsToSegmentBitshift
	} else if bitsPerSegment == 16 {
		decrement = fromIndex << ipv6BitsToSegmentBitshift
		totalBits = endIndex << ipv6BitsToSegmentBitshift
	} else {
		decrement = fromIndex * int(bitsPerSegment)
		totalBits = endIndex * int(bitsPerSegment)
	}

	return getDivisionPrefixLength(BitCount(totalBits), prefixLength-BitCount(decrement))
}

// getNetworkPrefixLen translates a non-nil segment prefix length into an address prefix length.
// When calling this for the first segment with a non-nil prefix length, this gives the overall prefix length.
//
// Across an address prefixes are:
// IPv6: (nil):...:(nil):(1 to 16):(0):...:(0)
// or IPv4: ...(nil).(1 to 8).(0)...
func getNetworkPrefixLen(bitsPerSegment, segmentPrefixLength BitCount, segmentIndex int) PrefixLen {
	var increment BitCount

	if bitsPerSegment == 8 {
		increment = BitCount(segmentIndex) << ipv4BitsToSegmentBitshift
	} else if bitsPerSegment == 16 {
		increment = BitCount(segmentIndex) << ipv6BitsToSegmentBitshift
	} else {
		increment = BitCount(segmentIndex) * bitsPerSegment
	}

	return cacheBitCount(increment + segmentPrefixLength)
}

func getSegmentsBitCount(bitsPerSegment BitCount, segmentCount int) BitCount {
	if bitsPerSegment == 8 {
		return BitCount(segmentCount) << ipv4BitsToSegmentBitshift
	} else if bitsPerSegment == 16 {
		return BitCount(segmentCount) << ipv6BitsToSegmentBitshift
	}
	return BitCount(segmentCount) * bitsPerSegment
}
