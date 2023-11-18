package goip

import "math/big"

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
