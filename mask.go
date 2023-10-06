package goip

import "math/bits"

var (
	defaultMasker                               = extendedMaskerBase{maskerBase{true}}
	defaultNonSequentialMasker                  = extendedMaskerBase{}
	defaultOrMasker                             = bitwiseOrerBase{true}
	defaultNonSequentialOrMasker                = bitwiseOrerBase{}
	_                            Masker         = maskerBase{}
	_                            Masker         = extendedMaskerBase{}
	_                            BitwiseOrer    = bitwiseOrerBase{}
	_                            ExtendedMasker = extendedMaskerBase{}
)

// BitwiseOrer is used for bitwise disjunction applied to division and segment values.
type BitwiseOrer interface {
	// GetOredLower provides the lowest value after the disjunction, which is not necessarily the lowest value apriori.
	GetOredLower(value, maskValue uint64) uint64
	// GetOredUpper provides the highest value after the disjunction, which is not necessarily the highest value apriori.
	GetOredUpper(upperValue, maskValue uint64) uint64
	// IsSequential returns whether applying bitwise disjunction to all values in the range results in a sequential set of values.
	IsSequential() bool
}

// Masker is used to mask (apply a bitwise combination) the division and segment values.
type Masker interface {
	// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
	GetMaskedLower(value, maskValue uint64) uint64
	// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
	GetMaskedUpper(upperValue, maskValue uint64) uint64
	// IsSequential returns whether masking all values in a range results in a consistent set of values.
	IsSequential() bool
}

type maskerBase struct {
	isSequentialVal bool
}

// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker maskerBase) GetMaskedLower(value, maskValue uint64) uint64 {
	return value & maskValue
}

// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker maskerBase) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return upperValue & maskValue
}

// IsSequential returns whether masking all values in a range results in a consistent set of values.
func (masker maskerBase) IsSequential() bool {
	return masker.isSequentialVal
}

// These can be cached by the int used to construct
type fullRangeMasker struct {
	maskerBase
	upperMask    uint64 // upperMask = ~0L >>> fullRangeBit;
	fullRangeBit int
}

// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker fullRangeMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedLower(value & ^masker.upperMask, maskValue)
}

// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker fullRangeMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedUpper(upperValue|masker.upperMask, maskValue)
}

type extendedMaskerBase struct {
	maskerBase
}

// GetExtendedMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker extendedMaskerBase) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return extendedValue & extendedMaskValue
}

// GetExtendedMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker extendedMaskerBase) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return extendedUpperValue & extendedMaskValue
}

type bitwiseOrerBase struct {
	isSequentialVal bool
}

func (masker bitwiseOrerBase) GetOredLower(value, maskValue uint64) uint64 {
	return value | maskValue
}

func (masker bitwiseOrerBase) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return upperValue | maskValue
}

// IsSequential returns whether masking all values in a range results in a consistent set of values.
func (masker bitwiseOrerBase) IsSequential() bool {
	return masker.isSequentialVal
}

type specificValueMasker struct {
	maskerBase
	lower uint64
	upper uint64
}

// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker specificValueMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedLower(value, maskValue)
}

// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker specificValueMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedUpper(upperValue, maskValue)
}

// ExtendedMasker handles value masking for divisions with bit counts larger than 64 bits.
type ExtendedMasker interface {
	Masker
	GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64
	GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64
}

func newFullRangeMasker(fullRangeBit int, isSequential bool) Masker {
	return fullRangeMasker{
		fullRangeBit: fullRangeBit,
		upperMask:    ^uint64(0) >> uint(fullRangeBit),
		maskerBase:   maskerBase{isSequential},
	}
}

func newSpecificValueMasker(lower, upper uint64) Masker {
	return specificValueMasker{lower: lower, upper: upper}
}

// MaskRange masks divisions with 64 bits or less. For larger divisions use MaskExtendedRange.
func MaskRange(value, upperValue, maskValue, maxValue uint64) Masker {
	if value == upperValue {
		return defaultMasker
	}

	if maskValue == 0 || maskValue == maxValue {
		return defaultMasker
	}

	// algorithm:
	// here find the highest bit that is in the range, highestDifferingBitInRange (i.e., changing from lower to higher)
	// then find the highest bit in the mask which is equal to 1, which is the same as or below highestDifferingBitInRange (if such a bit exists)

	// this gives us the highest bit which is part of the masked range (i.e. it changes from the lowest to the uppest bit after the mask is applied)
	// if this last bit exists, any bit below it in the mask must be 1 in order to remain consistent.

	differing := value ^ upperValue
	if differing != 1 {
		highestDifferingBitInRange := bits.LeadingZeros64(differing)
		maskMask := ^uint64(0) >> uint(highestDifferingBitInRange)
		differingMasked := maskValue & maskMask
		foundDiffering := differingMasked != 0
		if foundDiffering {
			// Anything below highestDifferingBitMasked in the mask must be ones.
			// Also, if we masked any bit 1 in the original, everything we don't mask must be ones.
			var hostMask uint64
			highestDifferingBitMasked := bits.LeadingZeros64(differingMasked) // first one bit in the mask covering the range
			if highestDifferingBitMasked != 63 {
				hostMask = ^uint64(0) >> uint(highestDifferingBitMasked+1)
			}
			// for the first mask bit that is 1, all bits that follow must also be 1
			maskedIsSequential := (maskValue & hostMask) == hostMask
			if maxValue == ^uint64(0) &&
				(!maskedIsSequential || highestDifferingBitMasked > highestDifferingBitInRange) {
				highestOneBit := bits.LeadingZeros64(upperValue)
				// note: highestOneBit < 64, otherwise differing would be 1 or 0
				maxValue = ^uint64(0) >> uint(highestOneBit)
			}

			if value == 0 && upperValue == maxValue {
				// full range
				if maskedIsSequential {
					return defaultMasker
				} else {
					return defaultNonSequentialMasker
				}
			}

			if highestDifferingBitMasked > highestDifferingBitInRange {
				if maskedIsSequential {
					// the count determines whether the masked range is sequential
					if highestDifferingBitMasked < 63 {
						count := upperValue - value + 1
						// If the original range is 0xxxxx to 1xxxxx, and our mask starts with single 0,
						// so the mask is 01111, then our new range covers at most 4 bits (could be less).
						// If the range covers 4 bits, we need to know if the range covers the same number of values as 0000-1111.
						// If so, the resulting range is not disjoint.
						// How do we know if the range is disjoint otherwise?
						// We know because it contains the values 1111 and 0000.
						// To go from 0xxxx to 1xxxx, we need to intersect consecutive values 01111 and 10000.
						// These values are consecutive in the original range (i.e., 01111 is followed by 10000),
						// but they are farthest apart in the new range,
						// and we need the whole range to fill the gap between them.
						// The number of values for the entire range is 1111 - 0000 + 1 = 10000
						// So, in this example, the first bit in the original range is bit 0, the largestDifferingBitMasked is 1,
						// and the range should cover 2 to the power of (5 - 1),
						// or 2 to the power of the number of bits - the largestDifferingBitMasked, or 1 shifted by so much.
						countRequiredForSequential := uint64(1) << uint(64-highestDifferingBitMasked)
						if count < countRequiredForSequential {
							// the resulting masked values are disjoint, not sequential
							maskedIsSequential = false
						}
					} // else count of 2 is good enough, even if the masked range does not cover both values, then the result will be a single value that is also sequential
				}
				// Part of the range of values will go from 0 to the mask itself.
				// This is because we know that if the range is from 0xxxx... to 1yyyy..., then 01111... and 10000... are also in the range,
				// because this is the only way to go from 0xxxx... to 1yyyy....
				// Since the mask does not have 1 bit in the top bit, we know that when masking with these two values 01111... and 10000...
				// we will get the mask itself and 00000 as the result.
				return newFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
			} else if !maskedIsSequential {
				hostZeroed := ^hostMask
				upperToBeMasked := upperValue & hostZeroed
				lowerToBeMasked := value | hostMask
				// find the value in the range, which, when masked, will give the highest and lowest values
				for nextBit := uint64(1) << (64 - uint(highestDifferingBitMasked+1) - 1); nextBit != 0; nextBit >>= 1 {
					// check if the bit in the mask is 1
					if (maskValue & nextBit) != 0 {
						candidate := upperToBeMasked | nextBit
						if candidate <= upperValue {
							upperToBeMasked = candidate
						}
						candidate = lowerToBeMasked & ^nextBit
						if candidate >= value {
							lowerToBeMasked = candidate
						}
					} //else
					// keep our upperToBeMasked bit as 0
					// keep our lowerToBeMasked bit as 1
				}
				return newSpecificValueMasker(lowerToBeMasked, upperToBeMasked)
			} // else fall through to default masker
		}
	}
	return defaultMasker
}
