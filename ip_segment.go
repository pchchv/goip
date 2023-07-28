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

func (seg *ipAddressSegmentInternal) isPrefixed() bool {
	return seg.GetSegmentPrefixLen() != nil
}

// IsPrefixBlock returns whether the segment has a prefix length and
// the segment range includes the block of values for that prefix length.
// If the prefix length matches the bit count, this returns true.
func (seg *ipAddressSegmentInternal) IsPrefixBlock() bool {
	return seg.isPrefixBlock()
}

// GetPrefixValueCount returns the count of prefixes in this segment for its prefix length,
// or the total count if it has no prefix length.
func (seg *ipAddressSegmentInternal) GetPrefixValueCount() SegIntCount {
	prefixLength := seg.GetSegmentPrefixLen()
	if prefixLength == nil {
		return seg.GetValueCount()
	}
	return getPrefixValueCount(seg.toAddressSegment(), prefixLength.bitCount())
}

// MatchesWithPrefixMask applies the network mask of the given bit-length to
// this segment and then compares the result with the given value masked by the same mask,
// returning true if the resulting range matches the given single value.
func (seg *ipAddressSegmentInternal) MatchesWithPrefixMask(value SegInt, networkBits BitCount) bool {
	mask := seg.GetSegmentNetworkMask(networkBits)
	matchingValue := value & mask
	return matchingValue == (seg.GetSegmentValue()&mask) && matchingValue == (seg.GetUpperSegmentValue()&mask)
}

// IsSinglePrefixBlock returns whether the range matches the value block for a single prefix identified by the prefix length of this address.
// This is similar to IsPrefixBlock, except that it returns false if the subnet has multiple prefixes.
//
// This method differs from ContainsSinglePrefixBlock in that it returns false if no prefix length is assigned to
// the series or the prefix length is different from the prefix length for which ContainsSinglePrefixBlock returns true.
//
// Method is similar to IsPrefixBlock, but returns false if there are multiple prefixes.
func (seg *ipAddressSegmentInternal) IsSinglePrefixBlock() bool {
	cache := seg.getCache()
	if cache != nil {
		res := cache.isSinglePrefBlock
		if res != nil {
			return *res
		}
	}
	if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
		return seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), prefLen.bitCount())
	}
	return false
}

func (seg *ipAddressSegmentInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	val := seg.GetSegmentValue()
	if val == 0 {
		networkMaskLen, hostMaskLen = cacheBitCount(0), cacheBitCount(seg.GetBitCount())
	} else {
		maxVal := seg.GetMaxValue()
		if val == maxVal {
			networkMaskLen, hostMaskLen = cacheBitCount(seg.GetBitCount()), cacheBitCount(0)
		} else {
			var shifted SegInt
			trailingOnes := seg.GetTrailingBitCount(true)
			if trailingOnes == 0 {
				// can only be 11110000 and not 00000000
				trailingZeros := seg.GetTrailingBitCount(false)
				shifted = (^val & maxVal) >> uint(trailingZeros)
				if shifted == 0 {
					networkMaskLen = cacheBitCount(seg.GetBitCount() - trailingZeros)
				}
			} else {
				// can only be 00001111 and not 11111111
				shifted = val >> uint(trailingOnes)
				if shifted == 0 {
					hostMaskLen = cacheBitCount(seg.GetBitCount() - trailingOnes)
				}
			}
		}
	}
	return
}
