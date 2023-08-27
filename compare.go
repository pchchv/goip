package goip

import "math/big"

type componentComparator interface {
	compareSectionParts(one, two *AddressSection) int
	compareParts(one, two AddressDivisionSeries) int
	compareSegValues(oneUpper, oneLower, twoUpper, twoLower SegInt) int
	compareValues(oneUpper, oneLower, twoUpper, twoLower uint64) int
	compareLargeValues(oneUpper, oneLower, twoUpper, twoLower *big.Int) int
}

// AddressComparator has methods for comparing addresses, or sections, or series of divisions, or segments, or divisions, or consecutive ranges.
// The AddressComparator also allows any two instances of any such address items to be compared using the Compare method.
// A zero value acts as CountComparator, the default comparator.
type AddressComparator struct {
	componentComparator componentComparator
}

type countComparator struct{}

func (countComparator) compareLargeValues(oneUpper, oneLower, twoUpper, twoLower *big.Int) (result int) {
	oneUpper.Sub(oneUpper, oneLower)
	twoUpper.Sub(twoUpper, twoLower)
	result = oneUpper.CmpAbs(twoUpper)
	if result == 0 {
		//the size of the range is the same, so just compare either upper or lower values
		result = oneLower.CmpAbs(twoLower)
	}
	return
}

func (countComparator) compareValues(oneUpper, oneLower, twoUpper, twoLower uint64) int {
	size1 := oneUpper - oneLower
	size2 := twoUpper - twoLower

	if size1 == size2 {
		if oneLower == twoLower {
			return 0
		} else if oneLower > twoLower {
			return 1
		}
	} else if size1 > size2 {
		return 1
	}

	return -1
}

func (comp countComparator) compareDivisionGroupings(oneSeries, twoSeries AddressDivisionSeries) int {
	var one, two *AddressDivisionGrouping

	if o, ok := oneSeries.(StandardDivGroupingType); ok {
		if t, ok := twoSeries.(StandardDivGroupingType); ok {
			one = o.ToDivGrouping()
			two = t.ToDivGrouping()
		}
	}

	if result := compareDivBitCounts(oneSeries, twoSeries); result != 0 {
		return result
	}

	oneSeriesByteCount := oneSeries.GetByteCount()
	twoSeriesByteCount := twoSeries.GetByteCount()

	oneUpperBytes := make([]byte, oneSeriesByteCount)
	oneLowerBytes := make([]byte, oneSeriesByteCount)
	twoUpperBytes := make([]byte, twoSeriesByteCount)
	twoLowerBytes := make([]byte, twoSeriesByteCount)

	var (
		oneByteCount, twoByteCount, oneByteIndex, twoByteIndex, oneIndex, twoIndex int
		oneBitCount, twoBitCount, oneTotalBitCount, twoTotalBitCount               BitCount
		oneUpper, oneLower, twoUpper, twoLower                                     uint64
	)

	for oneIndex < oneSeries.GetDivisionCount() || twoIndex < twoSeries.GetDivisionCount() {
		if one != nil {
			if oneBitCount == 0 {
				oneCombo := one.getDivision(oneIndex)
				oneIndex++
				oneBitCount = oneCombo.GetBitCount()
				oneUpper = oneCombo.GetUpperDivisionValue()
				oneLower = oneCombo.GetDivisionValue()
			}
			if twoBitCount == 0 {
				twoCombo := two.getDivision(twoIndex)
				twoIndex++
				twoBitCount = twoCombo.GetBitCount()
				twoUpper = twoCombo.GetUpperDivisionValue()
				twoLower = twoCombo.GetDivisionValue()
			}
		} else {
			if oneBitCount == 0 {
				if oneByteCount == 0 {
					oneCombo := oneSeries.GetGenericDivision(oneIndex)
					oneIndex++
					oneUpperBytes = oneCombo.CopyUpperBytes(oneUpperBytes)
					oneLowerBytes = oneCombo.CopyBytes(oneLowerBytes)
					oneTotalBitCount = oneCombo.GetBitCount()
					oneByteCount = oneCombo.GetByteCount()
					oneByteIndex = 0
				}
				// put some or all of the bytes into a uint64
				count := 8
				oneUpper = 0
				oneLower = 0
				if count < oneByteCount {
					oneBitCount = BitCount(count << 3)
					oneTotalBitCount -= oneBitCount
					oneByteCount -= count
					for count > 0 {
						count--
						upperByte := oneUpperBytes[oneByteIndex]
						lowerByte := oneLowerBytes[oneByteIndex]
						oneByteIndex++
						oneUpper = (oneUpper << 8) | uint64(upperByte)
						oneLower = (oneLower << 8) | uint64(lowerByte)
					}
				} else {
					shortCount := oneByteCount - 1
					lastBitsCount := oneTotalBitCount - (BitCount(shortCount) << 3)
					for shortCount > 0 {
						shortCount--
						upperByte := oneUpperBytes[oneByteIndex]
						lowerByte := oneLowerBytes[oneByteIndex]
						oneByteIndex++
						oneUpper = (oneUpper << 8) | uint64(upperByte)
						oneLower = (oneLower << 8) | uint64(lowerByte)
					}
					upperByte := oneUpperBytes[oneByteIndex]
					lowerByte := oneLowerBytes[oneByteIndex]
					oneByteIndex++
					oneUpper = (oneUpper << uint(lastBitsCount)) | uint64(upperByte>>uint(8-lastBitsCount))
					oneLower = (oneLower << uint(lastBitsCount)) | uint64(lowerByte>>uint(8-lastBitsCount))
					oneBitCount = oneTotalBitCount
					oneTotalBitCount = 0
					oneByteCount = 0
				}
			}

			if twoBitCount == 0 {
				if twoByteCount == 0 {
					twoCombo := twoSeries.GetGenericDivision(twoIndex)
					twoIndex++
					twoUpperBytes = twoCombo.CopyUpperBytes(twoUpperBytes)
					twoLowerBytes = twoCombo.CopyBytes(twoLowerBytes)
					twoTotalBitCount = twoCombo.GetBitCount()
					twoByteCount = twoCombo.GetByteCount()
					twoByteIndex = 0
				}
				// put some or all of the bytes into a long
				count := 8
				twoUpper = 0
				twoLower = 0
				if count < twoByteCount {
					twoBitCount = BitCount(count << 3)
					twoTotalBitCount -= twoBitCount
					twoByteCount -= count
					for count > 0 {
						count--
						upperByte := twoUpperBytes[twoByteIndex]
						lowerByte := twoLowerBytes[twoByteIndex]
						twoByteIndex++
						twoUpper = (twoUpper << 8) | uint64(upperByte)
						twoLower = (twoLower << 8) | uint64(lowerByte)
					}
				} else {
					shortCount := twoByteCount - 1
					lastBitsCount := twoTotalBitCount - (BitCount(shortCount) << 3)
					for shortCount > 0 {
						shortCount--
						upperByte := twoUpperBytes[twoByteIndex]
						lowerByte := twoLowerBytes[twoByteIndex]
						twoByteIndex++
						twoUpper = (twoUpper << 8) | uint64(upperByte)
						twoLower = (twoLower << 8) | uint64(lowerByte)
					}
					upperByte := twoUpperBytes[twoByteIndex]
					lowerByte := twoLowerBytes[twoByteIndex]
					twoByteIndex++
					twoUpper = (twoUpper << uint(lastBitsCount)) | uint64(upperByte>>uint(8-lastBitsCount))
					twoLower = (twoLower << uint(lastBitsCount)) | uint64(lowerByte>>uint(8-lastBitsCount))
					twoBitCount = twoTotalBitCount
					twoTotalBitCount = 0
					twoByteCount = 0
				}
			}
		}

		oneResultUpper := oneUpper
		oneResultLower := oneLower
		twoResultUpper := twoUpper
		twoResultLower := twoLower

		if twoBitCount == oneBitCount {
			// no adjustment required, compare the values straight up
			oneBitCount = 0
			twoBitCount = 0
		} else {
			diffBits := twoBitCount - oneBitCount
			if diffBits > 0 {
				twoResultUpper >>= uint(diffBits) //look at the high bits only (we are comparing left to right, high to low)
				twoResultLower >>= uint(diffBits)
				mask := ^(^uint64(0) << uint(diffBits))
				twoUpper &= mask
				twoLower &= mask
				twoBitCount = diffBits
				oneBitCount = 0
			} else {
				diffBits = -diffBits
				oneResultUpper >>= uint(diffBits)
				oneResultLower >>= uint(diffBits)
				mask := ^(^uint64(0) << uint(diffBits))
				oneUpper &= mask
				oneLower &= mask
				oneBitCount = diffBits
				twoBitCount = 0
			}
		}

		if result := comp.compareValues(oneResultUpper, oneResultLower, twoResultUpper, twoResultLower); result != 0 {
			return result
		}
	}

	return 0
}

// compareDivBitCounts is called when we know that two series have the same bit size,
// need to check that the divisions also have the same bit size.
func compareDivBitCounts(oneSeries, twoSeries AddressDivisionSeries) int {
	count := oneSeries.GetDivisionCount()
	result := count - twoSeries.GetDivisionCount()
	if result == 0 {
		for i := 0; i < count; i++ {
			result = int(oneSeries.GetGenericDivision(i).GetBitCount() - twoSeries.GetGenericDivision(i).GetBitCount())
			if result != 0 {
				break
			}
		}
	}
	return result
}

// Note: never called with an address instance, never called with an instance of AddressType
func getCount(item AddressItem) (b *big.Int, u uint64) {
	if sect, ok := item.(StandardDivGroupingType); ok {
		grouping := sect.ToDivGrouping()
		if grouping != nil {
			b = grouping.getCachedCount()
		}
	} else if rng, ok := item.(IPAddressSeqRangeType); ok {
		b = rng.GetCount()
	} else if div, ok := item.(StandardDivisionType); ok {
		base := div.ToDiv()
		if base != nil {
			if segBase := base.ToSegmentBase(); segBase != nil {
				u = uint64((segBase.getUpperSegmentValue() - base.getSegmentValue()) + 1)
			} else {
				r := base.getUpperDivisionValue() - base.getDivisionValue()
				if r == 0xffffffffffffffff {
					b = bigZero().SetUint64(0xffffffffffffffff)
					b.Add(b, bigOneConst())
					return
				}
				u = r + 1
			}
		}
	} else if lgrouping, ok := item.(*IPAddressLargeDivisionGrouping); ok {
		if lgrouping != nil {
			b = lgrouping.getCachedCount()
		}
	} else if ldiv, ok := item.(*IPAddressLargeDivision); ok {
		if ldiv != nil {
			b = ldiv.getCount()
		}
	} else {
		b = item.GetCount()
	}
	return
}

func isNilItem(item AddressItem) bool {
	if divSeries, ok := item.(AddressDivisionSeries); ok {
		if addr, ok := divSeries.(AddressType); ok {
			return addr.ToAddressBase() == nil
		} else if grouping, ok := divSeries.(StandardDivGroupingType); ok {
			return grouping.ToDivGrouping() == nil
		} else if largeGrouping, ok := divSeries.(*IPAddressLargeDivisionGrouping); ok {
			return largeGrouping.isNil()
		} // else a type external to this library, which we cannot test for nil
		//} else if rng, ok := item.(IPAddressSeqRangeType); ok {
		//	return rng.ToIP() == nil
	} else if rng, ok := item.(IPAddressSeqRangeType); ok {
		return rng.ToIP() == nil
	} else if div, ok := item.(DivisionType); ok {
		if sdiv, ok := div.(StandardDivisionType); ok {
			return sdiv.ToDiv() == nil
		} else if ldiv, ok := div.(*IPAddressLargeDivision); ok {
			return ldiv.isNil()
		} // else a type external to this library, which we cannot test for nil
	}
	return item == nil
}
