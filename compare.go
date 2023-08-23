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
