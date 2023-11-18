package goip

import (
	"math"
	"math/big"
)

// checkOverflow returns true for overflow.
// Used by IPv4 and MAC.
func checkOverflow(increment int64, lowerValue, upperValue, countMinus1 uint64, maxValue uint64) bool {
	if increment < 0 {
		if lowerValue < uint64(-increment) {
			return true
		}
	} else {
		uIncrement := uint64(increment)
		if uIncrement > countMinus1 {
			if countMinus1 > 0 {
				uIncrement -= countMinus1
			}
			room := maxValue - upperValue
			if uIncrement > room {
				return true
			}
		}
	}
	return false
}

// Used by MAC and IPv6.
func checkOverflowBig(increment int64, bigIncrement, lowerValue, upperValue, count *big.Int, maxValue func() *big.Int) bool {
	isMultiple := count.CmpAbs(bigOneConst()) > 0
	if increment < 0 {
		if lowerValue.CmpAbs(bigIncrement.Neg(bigIncrement)) < 0 {
			return true
		}
	} else {
		if isMultiple {
			bigIncrement.Sub(bigIncrement, count.Sub(count, bigOneConst()))
		}
		maxVal := maxValue()
		if bigIncrement.CmpAbs(maxVal.Sub(maxVal, upperValue)) > 0 {
			return true
		}
	}
	return false
}

// rangeIncrement the positive value of the number of increments through the range (0 means take lower or upper value in range)
func incrementRange(section *AddressSection, increment int64, lowerProducer func() *AddressSection, prefixLength PrefixLen) *AddressSection {
	if increment == 0 {
		return lowerProducer()
	}

	segCount := section.GetSegmentCount()
	newSegments := make([]*AddressDivision, segCount)
	for i := segCount - 1; i >= 0; i-- {
		seg := section.GetSegment(i)
		segRange := seg.GetValueCount()
		segRange64 := int64(segRange)
		revolutions := increment / segRange64
		remainder := increment % segRange64
		val := seg.getSegmentValue() + SegInt(remainder)
		segPrefixLength := getSegmentPrefixLength(section.GetBitsPerSegment(), prefixLength, i)
		newSegment := createAddressDivision(seg.deriveNewMultiSeg(val, val, segPrefixLength))
		newSegments[i] = newSegment
		if revolutions == 0 {
			for i--; i >= 0; i-- {
				original := section.GetSegment(i)
				val = original.getSegmentValue()
				segPrefixLength = getSegmentPrefixLength(section.GetBitsPerSegment(), prefixLength, i)
				newSegment = createAddressDivision(seg.deriveNewMultiSeg(val, val, segPrefixLength))
				newSegments[i] = newSegment
			}
			break
		} else {
			increment = revolutions
		}
	}
	return createSection(newSegments, prefixLength, section.getAddrType())
}

func add(section *AddressSection, fullValue uint64, increment int64, creator addressSegmentCreator, prefixLength PrefixLen) *AddressSection {
	var val uint64
	segCount := section.GetSegmentCount()
	if increment < 0 {
		val = fullValue - uint64(-increment)
	} else {
		val = fullValue + uint64(increment)
	}

	newSegs := createSegmentsUint64(
		segCount,
		0,
		val,
		section.GetBytesPerSegment(),
		section.GetBitsPerSegment(),
		creator,
		prefixLength)
	return createSection(newSegs, prefixLength, section.getAddrType())
}

// addBig does not handle overflow, overflow should be checked before calling this.
func addBig(section *AddressSection, increment *big.Int, creator addressSegmentCreator, prefixLength PrefixLen) *AddressSection {
	segCount := section.GetSegmentCount()
	fullValue := section.GetValue()
	fullValue.Add(fullValue, increment)
	expectedByteCount := section.GetByteCount()
	bytes := fullValue.Bytes() // could use FillBytes but that only came with 1.15
	segments, _ := toSegments(
		bytes,
		segCount,
		section.GetBytesPerSegment(),
		section.GetBitsPerSegment(),
		//expectedByteCount,
		creator,
		prefixLength)
	res := createSection(segments, prefixLength, section.getAddrType())
	if expectedByteCount == len(bytes) && res.cache != nil {
		res.cache.bytesCache = &bytesCache{
			lowerBytes: bytes,
			upperBytes: bytes,
		}
	}
	return res
}

// increment does not handle overflow,
// overflow should be checked before calling this.
// Used by IPv4 and MAC.
func increment(section *AddressSection, increment int64, creator addressSegmentCreator, countMinus1 uint64, lowerValue, upperValue uint64, lowerProducer, upperProducer func() *AddressSection, prefixLength PrefixLen) *AddressSection {
	if !section.isMultiple() {
		return add(section, lowerValue, increment, creator, prefixLength)
	}

	isDecrement := increment <= 0
	if isDecrement {
		//we know lowerValue + increment >= 0 because we already did an overflow check
		return add(lowerProducer(), lowerValue, increment, creator, prefixLength)
	}

	uIncrement := uint64(increment)
	if countMinus1 >= uIncrement {
		if countMinus1 == uIncrement {
			return upperProducer()
		}
		return incrementRange(section, increment, lowerProducer, prefixLength)
	}

	if uIncrement <= math.MaxUint64-upperValue {
		return add(upperProducer(), upperValue, int64(uIncrement-countMinus1), creator, prefixLength)
	}

	return addBig(upperProducer(), new(big.Int).SetUint64(uIncrement-countMinus1), creator, prefixLength)
}

// fastIncrement handles the cases in which we can use longs rather than BigInteger.
// Used by IPv6.
func fastIncrement(section *AddressSection, inc int64, creator addressSegmentCreator, lowerProducer, upperProducer func() *AddressSection, prefixLength PrefixLen) *AddressSection {
	if inc >= 0 {
		var maxUint64 big.Int
		uincrement := uint64(inc)
		count := section.GetCount()
		maxUint64.SetUint64(math.MaxUint64)
		countMinus1 := count.Sub(count, bigOneConst())
		if countMinus1.CmpAbs(&maxUint64) <= 0 {
			longCount := count.Uint64()
			if longCount > uincrement {
				if longCount == uincrement+1 {
					return upperProducer()
				}
				return incrementRange(section, inc, lowerProducer, prefixLength)
			}
			upperValue := section.GetUpperValue()
			if upperValue.CmpAbs(&maxUint64) <= 0 {
				value := section.GetValue()
				return increment(
					section,
					inc,
					creator,
					countMinus1.Uint64(),
					value.Uint64(),
					upperValue.Uint64(),
					lowerProducer,
					upperProducer,
					prefixLength)
			}
		}
	} else {
		var maxUint64 big.Int
		maxUint64.SetUint64(math.MaxUint64)
		value := section.GetValue()
		if value.CmpAbs(&maxUint64) <= 0 {
			return add(lowerProducer(), value.Uint64(), inc, creator, prefixLength)
		}
	}
	return nil
}

// incrementBig does not handle overflow,
// overflow should be checked before calling this.
// Used by MAC and IPv6
func incrementBig(section *AddressSection, increment int64, bigIncrement *big.Int, creator addressSegmentCreator, lowerProducer, upperProducer func() *AddressSection, prefixLength PrefixLen) *AddressSection {
	if !section.isMultiple() {
		return addBig(section, bigIncrement, creator, prefixLength)
	}

	isDecrement := increment <= 0
	if isDecrement {
		return addBig(lowerProducer(), bigIncrement, creator, prefixLength)
	}

	count := section.GetCount()
	incrementPlus1 := bigIncrement.Add(bigIncrement, bigOneConst())
	countCompare := count.CmpAbs(incrementPlus1)
	if countCompare <= 0 {
		if countCompare == 0 {
			return upperProducer()
		}
		return addBig(upperProducer(), incrementPlus1.Sub(incrementPlus1, count), creator, prefixLength)
	}

	return incrementRange(section, increment, lowerProducer, prefixLength)
}
