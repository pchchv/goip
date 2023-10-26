package goip

// SequentialRangeKey is a representation of SequentialRange that is comparable as defined by the language specification.
//
// It can be used as a map key.
// The zero value is a range from a zero-length address to itself.
type SequentialRangeKey[T SequentialRangeConstraint[T]] struct {
	vals [2]struct {
		lower,
		upper uint64
	}
	addrType addrType // only used when T is *IPAddress to indicate version for non-zero valued address
}

// ToSeqRange converts back to a sequential range instance.
func (key SequentialRangeKey[T]) ToSeqRange() *SequentialRange[T] {
	var isMult bool
	var lower, upper T
	anyt := any(lower)
	isIP, isIPv4, isIPv6 := false, false, false
	if _, isIPv4 = anyt.(*IPv4Address); !isIPv4 {
		if _, isIPv6 = anyt.(*IPv6Address); !isIPv6 {
			if _, isIP = anyt.(*IPAddress); isIP {
				addressType := key.addrType
				if isIPv4 = addressType.isIPv4(); !isIPv4 {
					if isIPv6 = addressType.isIPv6(); !isIPv6 {
						if isNeither := addressType.isZeroSegments(); isNeither {
							lower = any(zeroIPAddr).(T)
							upper = lower
						} else {
							panic("supports only IP addresses")
						}
					}
				}
			} else {
				panic("supports only IP addresses")
			}
		}
	}

	if isIPv6 {
		lower6 := NewIPv6AddressFromVals(
			func(segmentIndex int) IPv6SegInt {
				valsIndex := segmentIndex >> 2
				segIndex := ((IPv6SegmentCount - 1) - segmentIndex) & 0x3
				return IPv6SegInt(key.vals[valsIndex].lower >> (segIndex << ipv6BitsToSegmentBitshift))
			})
		upper6 := NewIPv6AddressFromVals(
			func(segmentIndex int) IPv6SegInt {
				valsIndex := segmentIndex >> 2
				segIndex := ((IPv6SegmentCount - 1) - segmentIndex) & 0x3
				return IPv6SegInt(key.vals[valsIndex].upper >> (segIndex << ipv6BitsToSegmentBitshift))
			})
		isMult = key.vals[1].lower != key.vals[1].upper || key.vals[0].lower != key.vals[0].upper
		if isIP {
			lower = any(lower6.ToIP()).(T)
			upper = any(upper6.ToIP()).(T)
		} else {
			lower = any(lower6).(T)
			upper = any(upper6).(T)
		}
	} else if isIPv4 {
		l := uint32(key.vals[0].lower)
		u := uint32(key.vals[0].upper)
		lower4 := NewIPv4AddressFromUint32(l)
		upper4 := NewIPv4AddressFromUint32(u)
		isMult = l != u
		if isIP {
			lower = any(lower4.ToIP()).(T)
			upper = any(upper4.ToIP()).(T)
		} else {
			lower = any(lower4).(T)
			upper = any(upper4).(T)
		}
	}

	return newSequRangeUnchecked(lower, upper, isMult)
}

// String calls the String method in the corresponding sequential range.
func (key SequentialRangeKey[T]) String() string {
	return key.ToSeqRange().String()
}
