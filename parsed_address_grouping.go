package goip

import "math/bits"

const (
	zerosOnly = subnetOption(iota)
	fullRangeOnly
	zerosToFullRange
	zerosOrFullRange
)

type subnetOption int

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
	var decrement, totalBits int
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

// For explicit prefix config this always returns false.
// For all prefix subnets config this always returns true if the prefix length does not extend beyond the address end.
func isPrefixSubnet(
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	segmentMaxValue SegInt,
	prefLen BitCount,
	subnetOption subnetOption) bool {

	if prefLen < 0 {
		prefLen = 0
	} else {
		var totalBitCount BitCount
		if bitsPerSegment == 8 {
			totalBitCount = BitCount(segmentCount) << ipv4BitsToSegmentBitshift
		} else if bitsPerSegment == 16 {
			totalBitCount = BitCount(segmentCount) << ipv6BitsToSegmentBitshift
		} else {
			totalBitCount = BitCount(segmentCount) * bitsPerSegment
		}
		if prefLen >= totalBitCount {
			return false
		}
	}

	prefixedSegment := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
	i := prefixedSegment
	if i < segmentCount {
		zero := PrefixBitCount(0)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, i)
		for {
			// we want to see if there is a sequence of zeros followed by a sequence of full-range bits from the prefix onwards
			// once we start seeing full range bits, the remained of the section must be full range
			// for instance x marks the start of zeros and y marks the start of full range:
			// segment 1 segment 2 ...
			// upper: 10101010  10100111 11111111 11111111
			// lower: 00111010  00100000 00000000 00000000
			//                     x y
			// upper: 10101010  10100000 00000000 00111111
			// lower: 00111010  00100000 10000000 00000000
			//                            x         y
			//
			// the bit marked x in each set of 4 segment of 8 bits is a sequence of zeros,
			// followed by full range bits starting at bit y
			lower := lowerValueProvider(i)
			prefLen := segmentPrefixLength.bitCount()
			if prefLen == 0 {
				if lower != 0 {
					return false
				}
				upper := upperValueProvider(i)
				if subnetOption == fullRangeOnly {
					if upper != segmentMaxValue {
						return false
					}
				} else if upper != 0 {
					if subnetOption == zerosOnly {
						return false
					} else if upper == segmentMaxValue {
						if subnetOption == zerosOrFullRange && i > prefixedSegment {
							return false
						}
					} else if subnetOption == zerosOrFullRange {
						return false
					} else { //zerosToFullRange
						upperTrailingOnes := bits.TrailingZeros64(^uint64(upper))
						if (upper >> uint(upperTrailingOnes)) != 0 {
							return false
						}
					}
					subnetOption = fullRangeOnly
				}
			} else if prefLen < bitsPerSegment {
				segHostBits := bitsPerSegment - prefLen
				hostMask := ^(^SegInt(0) << uint(segHostBits))
				if (hostMask & lower) != 0 {
					return false
				}
				upper := upperValueProvider(i)
				if subnetOption == fullRangeOnly {
					if (hostMask & upper) != hostMask {
						return false
					}
				} else {
					hostUpper := hostMask & upper
					if hostUpper != 0 {
						if subnetOption == zerosOnly {
							return false
						} else if hostUpper == hostMask {
							if subnetOption == zerosOrFullRange && i > prefixedSegment {
								return false
							}
						} else if subnetOption == zerosOrFullRange {
							return false
						} else { // zerosToFullRange
							upperTrailingOnes := uint(bits.TrailingZeros64(^uint64(upper)))
							hostMask >>= upperTrailingOnes
							upper >>= upperTrailingOnes
							if (hostMask & upper) != 0 {
								return false
							}
						}
						subnetOption = fullRangeOnly
					}
				}
			}
			segmentPrefixLength = &zero
			i++
			if i >= segmentCount {
				break
			}
		}
	}
	return true
}

func getTotalBits(segmentCount, bytesPerSegment int, bitsPerSegment BitCount) BitCount {
	if bytesPerSegment != 1 {
		if bytesPerSegment == 2 {
			return BitCount(segmentCount << ipv6BitsToSegmentBitshift)
		}
		return BitCount(segmentCount * bitsPerSegment)
	}
	return BitCount(segmentCount << ipv4BitsToSegmentBitshift)
}
