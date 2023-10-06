package goip

import (
	"math/big"
	"math/bits"
)

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

// fullRangeBitwiseOrer can be cached by the int used to construct.
type fullRangeBitwiseOrer struct {
	bitwiseOrerBase
	upperMask    uint64
	fullRangeBit int
}

func (masker fullRangeBitwiseOrer) GetOredLower(value, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredLower(value & ^masker.upperMask, maskValue)
}

func (masker fullRangeBitwiseOrer) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredUpper(upperValue|masker.upperMask, maskValue)
}

type specificValueBitwiseOrer struct {
	bitwiseOrerBase
	lower uint64
	upper uint64
}

func (masker specificValueBitwiseOrer) GetOredLower(value, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredLower(value, maskValue)
}

func (masker specificValueBitwiseOrer) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return masker.bitwiseOrerBase.GetOredUpper(upperValue, maskValue)
}

// extendedFullRangeMasker can be cached by the int used to construct.
type extendedFullRangeMasker struct {
	extendedMaskerBase
	upperMask         uint64
	extendedUpperMask uint64
}

// GetMaskedLower provides the lowest masked value,
// which is not necessarily the lowest value masked.
func (masker extendedFullRangeMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedLower(value & ^masker.upperMask, maskValue)
}

// GetMaskedUpper provides the highest masked value,
// which is not necessarily the highest value masked.
func (masker extendedFullRangeMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedUpper(upperValue|masker.upperMask, maskValue)
}

// GetExtendedMaskedLower provides the lowest masked value, which is not necessarily the lowest value masked.
func (masker extendedFullRangeMasker) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedLower(extendedValue & ^masker.extendedUpperMask, extendedMaskValue)
}

// GetExtendedMaskedUpper provides the highest masked value, which is not necessarily the highest value masked.
func (masker extendedFullRangeMasker) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedUpper(extendedUpperValue|masker.extendedUpperMask, extendedMaskValue)
}

type wrappedMasker struct {
	extendedMaskerBase
	masker Masker
}

func (masker wrappedMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.masker.GetMaskedLower(value, maskValue)
}

func (masker wrappedMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.masker.GetMaskedUpper(upperValue, maskValue)
}

// extendedSpecificValueMasker can be cached by the int used to construct.
type extendedSpecificValueMasker struct {
	extendedMaskerBase
	lower         uint64
	upper         uint64
	extendedLower uint64
	extendedUpper uint64
}

func (masker extendedSpecificValueMasker) GetMaskedLower(_, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedLower(masker.lower, maskValue)
}

func (masker extendedSpecificValueMasker) GetMaskedUpper(_, maskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetMaskedUpper(masker.upper, maskValue)
}

func (masker extendedSpecificValueMasker) GetExtendedMaskedLower(_, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedLower(masker.extendedLower, extendedMaskValue)
}

func (masker extendedSpecificValueMasker) GetExtendedMaskedUpper(_, extendedMaskValue uint64) uint64 {
	return masker.extendedMaskerBase.GetExtendedMaskedUpper(masker.extendedUpper, extendedMaskValue)
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

func newWrappedMasker(masker Masker) ExtendedMasker {
	return wrappedMasker{
		extendedMaskerBase: extendedMaskerBase{maskerBase{masker.IsSequential()}},
		masker:             masker,
	}
}

func newExtendedFullRangeMasker(fullRangeBit int, isSequential bool) ExtendedMasker {
	var upperMask, extendedUpperMask uint64

	if fullRangeBit >= 64 {
		upperMask = ^uint64(0) >> (uint(fullRangeBit) - 64)
	} else {
		extendedUpperMask = ^uint64(0) >> uint(fullRangeBit)
		upperMask = 0xffffffffffffffff
	}

	return extendedFullRangeMasker{
		extendedUpperMask:  extendedUpperMask,
		upperMask:          upperMask,
		extendedMaskerBase: extendedMaskerBase{maskerBase{isSequential}},
	}
}

func newExtendedSpecificValueMasker(extendedLower, lower, extendedUpper, upper uint64) ExtendedMasker {
	return extendedSpecificValueMasker{
		extendedLower: extendedLower,
		lower:         lower,
		extendedUpper: extendedUpper,
		upper:         upper,
	}
}

func newFullRangeBitwiseOrer(fullRangeBit int, isSequential bool) BitwiseOrer {
	return fullRangeBitwiseOrer{
		fullRangeBit:    fullRangeBit,
		upperMask:       ^uint64(0) >> uint(fullRangeBit),
		bitwiseOrerBase: bitwiseOrerBase{isSequential},
	}
}

// MaskExtendedRange masks divisions with bit counts larger than 64 bits. Use MaskRange for smaller divisions.
func MaskExtendedRange(value, extendedValue, upperValue, extendedUpperValue, maskValue, extendedMaskValue, maxValue, extendedMaxValue uint64) ExtendedMasker {
	//algorithm:
	//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
	//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
	//
	//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
	//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.
	extendedDiffering := extendedValue ^ extendedUpperValue
	if extendedDiffering == 0 {
		// the top is single-valued so just need to check the lower part
		masker := MaskRange(value, upperValue, maskValue, maxValue)
		if masker == defaultMasker {
			return defaultMasker
		}
		return newWrappedMasker(masker)
	}

	if (maskValue == maxValue && extendedMaskValue == extendedMaxValue /* all ones mask */) ||
		(maskValue == 0 && extendedMaskValue == 0 /* all zeros mask */) {
		return defaultMasker
	}

	var highestDifferingBitMasked int
	highestDifferingBitInRange := bits.LeadingZeros64(extendedDiffering)
	extendedDifferingMasked := extendedMaskValue & (^uint64(0) >> uint(highestDifferingBitInRange))
	if extendedDifferingMasked != 0 {
		var maskedIsSequential bool
		differingIsLowestBit := extendedDifferingMasked == 1
		hostMask := ^uint64(0) >> uint(highestDifferingBitMasked+1)
		highestDifferingBitMasked = bits.LeadingZeros64(extendedDifferingMasked)
		if !differingIsLowestBit { // Anything below highestDifferingBitMasked in the mask must be ones.
			//for the first mask bit that is 1, all bits that follow must also be 1
			maskedIsSequential = (extendedMaskValue&hostMask) == hostMask && maskValue == maxValue //check if all ones below
		} else {
			maskedIsSequential = maskValue == maxValue
		}

		if value == 0 && extendedValue == 0 &&
			upperValue == maxValue && extendedUpperValue == extendedMaxValue {
			// full range
			if maskedIsSequential {
				return defaultMasker
			}
			return defaultNonSequentialMasker
		}

		if highestDifferingBitMasked > highestDifferingBitInRange {
			if maskedIsSequential {
				// We need to check that the range is larger enough that when chopping off the top it remains sequential
				//
				// Note: a count of 2 in the extended could equate to a count of 2 total!
				// upper: xxxxxxx1 00000000
				// lower: xxxxxxx0 11111111
				// Or, it could be everything:
				// upper: xxxxxxx1 11111111
				// lower: xxxxxxx0 00000000
				// So for that reason, we need to check the full count here and not just extended
				countRequiredForSequential := bigOne()
				countRequiredForSequential.Lsh(countRequiredForSequential, 128-uint(highestDifferingBitMasked))

				var upperBig, lowerBig, val big.Int
				upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
				lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))
				count := upperBig.Sub(&upperBig, &lowerBig).Add(&upperBig, bigOne())
				maskedIsSequential = count.CmpAbs(countRequiredForSequential) >= 0
			}
			return newExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
		} else if !maskedIsSequential {

			var bigHostZeroed, bigHostMask, val big.Int
			bigHostMask.SetUint64(hostMask).Lsh(&bigHostMask, 64).Or(&bigHostMask, val.SetUint64(^uint64(0)))
			bigHostZeroed.Not(&bigHostMask)

			var upperBig, lowerBig big.Int
			upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
			lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))

			var upperToBeMaskedBig, lowerToBeMaskedBig, maskBig big.Int
			upperToBeMaskedBig.And(&upperBig, &bigHostZeroed)
			lowerToBeMaskedBig.Or(&lowerBig, &bigHostMask)
			maskBig.SetUint64(extendedMaskValue).Lsh(&maskBig, 64).Or(&maskBig, val.SetUint64(maskValue))

			for nextBit := 128 - (highestDifferingBitMasked + 1) - 1; nextBit >= 0; nextBit-- {
				// check if the bit in the mask is 1
				if maskBig.Bit(nextBit) != 0 {
					val.Set(&upperToBeMaskedBig).SetBit(&val, nextBit, 1)
					if val.CmpAbs(&upperBig) <= 0 {
						upperToBeMaskedBig.Set(&val)
					}
					val.Set(&lowerToBeMaskedBig).SetBit(&val, nextBit, 0)
					if val.CmpAbs(&lowerBig) >= 0 {
						lowerToBeMaskedBig.Set(&val)
					}
				}
			}

			var lowerMaskedBig, upperMaskedBig big.Int
			lowerMaskedBig.Set(&lowerToBeMaskedBig).And(&lowerToBeMaskedBig, val.SetUint64(^uint64(0)))
			upperMaskedBig.Set(&upperToBeMaskedBig).And(&upperToBeMaskedBig, &val)

			return newExtendedSpecificValueMasker(
				lowerToBeMaskedBig.Rsh(&lowerToBeMaskedBig, 64).Uint64(),
				lowerMaskedBig.Uint64(),
				upperToBeMaskedBig.Rsh(&upperToBeMaskedBig, 64).Uint64(),
				upperMaskedBig.Uint64())

		}
		return defaultMasker
	}
	// When masking, the top becomes single-valued.
	//
	// We go to the lower values to find highestDifferingBitMasked.
	//
	// At this point, the highest differing bit in the lower range is 0
	// and the highestDifferingBitMasked is the first 1 bit in the lower mask
	if maskValue == 0 {
		// the mask zeroes out everything,
		return defaultMasker
	}

	maskedIsSequential := true
	highestDifferingBitMaskedLow := bits.LeadingZeros64(maskValue)
	if maskValue != maxValue && highestDifferingBitMaskedLow < 63 {
		//for the first mask bit that is 1, all bits that follow must also be 1
		hostMask := ^uint64(0) >> uint(highestDifferingBitMaskedLow+1) // this shift of since case of highestDifferingBitMaskedLow of 64 and 63 taken care of, so the shift is < 64
		maskedIsSequential = (maskValue & hostMask) == hostMask        //check if all ones below
	}

	if maskedIsSequential {
		//Note: a count of 2 in the lower values could equate to a count of everything in the full range:
		//upper: xxxxxx10 00000000
		//lower: xxxxxxx0 11111111
		//Another example:
		//upper: xxxxxxx1 00000001
		//lower: xxxxxxx0 00000000
		//So for that reason, we need to check the full count here and not just lower values
		//
		//We need to check that the range is larger enough that when chopping off the top it remains sequential
		countRequiredForSequential := bigOne()
		countRequiredForSequential.Lsh(countRequiredForSequential, 64-uint(highestDifferingBitMaskedLow))

		var upperBig, lowerBig, val big.Int
		upperBig.SetUint64(extendedUpperValue).Lsh(&upperBig, 64).Or(&upperBig, val.SetUint64(upperValue))
		lowerBig.SetUint64(extendedValue).Lsh(&lowerBig, 64).Or(&lowerBig, val.SetUint64(value))
		count := upperBig.Sub(&upperBig, &lowerBig).Add(&upperBig, bigOne())
		maskedIsSequential = count.CmpAbs(countRequiredForSequential) >= 0
	}
	highestDifferingBitMasked = highestDifferingBitMaskedLow + 64
	return newExtendedFullRangeMasker(highestDifferingBitMasked, maskedIsSequential)
}

func newSpecificValueBitwiseOrer(lower, upper uint64) BitwiseOrer {
	return specificValueBitwiseOrer{lower: lower, upper: upper}
}
