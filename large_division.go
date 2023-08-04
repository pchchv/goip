package goip

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

var _ divisionValues = &largeDivValues{}

type BigDivInt = big.Int

type addressLargeDivInternal struct {
	addressDivisionBase
	defaultRadix *BigDivInt
}

func (div *addressLargeDivInternal) getDefaultRadix() int {
	rad := div.defaultRadix
	if rad == nil {
		return 16 // use same default as other divisions when zero div
	}
	return int(rad.Int64())
}

func (div *addressLargeDivInternal) toLargeAddressDivision() *IPAddressLargeDivision {
	return (*IPAddressLargeDivision)(unsafe.Pointer(div))
}

// getDefaultTextualRadix returns the default radix for textual representations of divisions.
func (div *addressLargeDivInternal) getDefaultTextualRadix() int {
	if div.divisionValues == nil || div.defaultRadix == nil {
		return 16 // use same default as other divisions when zero div
	}
	return int(div.defaultRadix.Int64())
}

func (div *addressLargeDivInternal) getLargeDivValues() *largeDivValues {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.(*largeDivValues)
}

// getBigDefaultTextualRadix returns the default radix for textual representations of divisions.
func (div *addressLargeDivInternal) getBigDefaultTextualRadix() *big.Int {
	if div.divisionValues == nil || div.defaultRadix == nil {
		return bigSixteen() // use same default as other divisions when zero div
	}
	return div.defaultRadix
}

// toString produces a string that is useful when a division string is provided with no context.
// It uses a string prefix for octal or hex ("0" or "0x"), and does not use the wildcard '*', because division size is variable, so '*' is ambiguous.
// GetWildcardString() is more appropriate in context with other segments or divisions.  It does not use a string prefix and uses '*' for full-range segments.
// GetString() is more appropriate in context with prefix lengths, it uses zeros instead of wildcards for prefix block ranges.
func (div *addressLargeDivInternal) toString() string { // this can be moved to addressDivisionBase when we have ContainsPrefixBlock and similar methods implemented for big.Int in the base
	return toString(div.toLargeAddressDivision())
}

// Format implements [fmt.Formatter] interface. It accepts the formats
//   - 'v' for the default address and section format (either the normalized or canonical string),
//   - 's' (string) for the same,
//   - 'b' (binary), 'o' (octal with 0 prefix), 'O' (octal with 0o prefix),
//   - 'd' (decimal), 'x' (lowercase hexadecimal), and
//   - 'X' (uppercase hexadecimal).
//
// Also supported are some of fmt's format flags for integral types.
// Sign control is not supported since addresses and sections are never negative.
// '#' for an alternate format is supported, which adds a leading zero for octal, and for hexadecimal it adds
// a leading "0x" or "0X" for "%#x" and "%#X" respectively.
// Also supported is specification of minimum digits precision, output field width,
// space or zero padding, and '-' for left or right justification.
func (div addressLargeDivInternal) Format(state fmt.State, verb rune) {
	switch verb {
	case 's', 'v':
		_, _ = state.Write([]byte(div.toString()))
		return
	}
	// we try to filter through the flags provided to the DivInt values, as if the fmt string were applied to the int(s) directly
	formatStr := flagsFromState(state, verb)
	if div.isMultiple() {
		formatStr = fmt.Sprintf("%s%c%s", formatStr, RangeSeparator, formatStr)
		_, _ = state.Write([]byte(fmt.Sprintf(formatStr, div.getValue(), div.getUpperValue())))
	} else {
		_, _ = state.Write([]byte(fmt.Sprintf(formatStr, div.getValue())))
	}
}

// IPAddressLargeDivision represents an arbitrary bit size division in an address or address division grouping.
// It can contain a single value or a range of consecutive values and has an assigned bit length.
// Like all address components, it is immutable.
type IPAddressLargeDivision struct {
	addressLargeDivInternal
}

// IsMultiple returns true if the given division represents a consecutive range of values or a single value.
func (div *IPAddressLargeDivision) IsMultiple() bool {
	return div != nil && div.isMultiple()
}

// IsPrefixed returns whether the given division has a prefix length associated with it.
// If so, the prefix length is given by GetDivisionPrefixLen()
func (div *IPAddressLargeDivision) IsPrefixed() bool {
	return div.GetDivisionPrefixLen() != nil
}

// GetDivisionPrefixLen returns the network prefix for the division.
// For an address like "1.2.0.0/16", the network prefix is 16.
// When it comes to each address subdivision or segment, the subdivision prefix is the prefix obtained by applying an address or partition prefix.
// For example, consider the address "1.2.0.0/20."
// The first segment has no prefix because the address prefix 20 is beyond the 8 bits in the first segment, it is not even applied to the segment.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which are in the second segment, it also does not apply to this segment.
// The third segment is prefixed with 4 because address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network portion of the address or segment.
// The last segment is prefixed with 0 because no bits are part of the network portion of the address or segment.
// The following division prefixes apply throughout the address: nil ... nil (1 to the bit length of the segment) 0 ... 0.
// If the division has no prefix, nil is returned.
func (div *IPAddressLargeDivision) GetDivisionPrefixLen() PrefixLen {
	return div.getDivisionPrefixLength()
}

// GetPrefixLen returns the network prefix for the unit.
// For an address like "1.2.0.0/16", the network prefix is 16.
// When it comes to each address subdivision or segment, the prefix for the subdivision is the prefix obtained when the address or partition prefix is applied.
// For example, consider the address "1.2.0.0/20".
// The first segment has no prefix because the address prefix 20 is beyond the 8 bits in the first segment, it is not even applied to the segment.
// The second segment has no prefix because the address prefix extends beyond bits 9 through 16,
// which are in the second segment, it also does not apply to this segment.
// The third segment is prefixed with 4 because address prefix 20 corresponds to the first 4 bits in the third segment,
// which means that the first 4 bits are part of the network portion of the address or segment.
// The last segment is prefixed with 0 because no bits are part of the network portion of the address or segment.
// The following division prefixes apply throughout the address: nil ... nil (1 to the bit length of the segment) 0 ... 0.
// If the segment has no prefix, nil is returned.
func (div *IPAddressLargeDivision) GetPrefixLen() PrefixLen {
	return div.getDivisionPrefixLength()
}

func (div *IPAddressLargeDivision) isNil() bool {
	return div == nil
}

// IsSinglePrefix returns true if the division value range spans
// just a single prefix value for the given prefix length.
func (div *IPAddressLargeDivision) IsSinglePrefix(divisionPrefixLen BitCount) bool {
	lower, upper := div.getValue(), div.getUpperValue()
	bitCount := div.GetBitCount()
	divisionPrefixLen = checkBitCount(divisionPrefixLen, bitCount)
	shift := uint(bitCount - divisionPrefixLen)
	var one, two big.Int
	return one.Rsh(lower, shift).Cmp(two.Rsh(upper, shift)) == 0
}

func (div *IPAddressLargeDivision) getBigRadix(radix int) *big.Int {
	defaultRadix := div.getDefaultTextualRadix()
	if defaultRadix == radix {
		return div.getBigDefaultTextualRadix()
	}
	return big.NewInt(int64(radix))
}

func (div *IPAddressLargeDivision) getRangeDigitCount(radix int) int {
	if !div.IsMultiple() {
		return 0
	}

	var quotient, upperQuotient, remainder big.Int
	val, upperVal := div.getValue(), div.getUpperValue()
	count := 1
	bigRadix := big.NewInt(int64(radix))
	bigUpperDigit := big.NewInt(int64(radix - 1))

	for {
		quotient.QuoRem(val, bigRadix, &remainder)
		if bigIsZero(&remainder) {
			upperQuotient.QuoRem(upperVal, bigRadix, &remainder)
			if remainder.CmpAbs(bigUpperDigit) == 0 {
				val, upperVal = &quotient, &upperQuotient
				if val.CmpAbs(upperVal) == 0 {
					return count
				} else {
					count++
					continue
				}
			}
		}
		return 0
	}
}

// IsPrefixBlock returns whether the division has a prefix length and
// the division range includes the block of values for that prefix length.
// If the prefix length matches the bit count, this returns true.
func (div *IPAddressLargeDivision) IsPrefixBlock() bool {
	return div.getLargeDivValues().isPrefixBlock
}

// IsSinglePrefixBlock returns whether the division range matches
// the block of values for its prefix length
func (div *IPAddressLargeDivision) IsSinglePrefixBlock() bool {
	return *div.getLargeDivValues().cache.isSinglePrefBlock
}

// GetValue returns the lowest value in the address division range as a big integer.
func (div *IPAddressLargeDivision) GetValue() *BigDivInt {
	return new(big.Int).Set(div.addressLargeDivInternal.GetValue())
}

// GetUpperValue returns the highest value in the address division range as a big integer.
func (div *IPAddressLargeDivision) GetUpperValue() *BigDivInt {
	return new(big.Int).Set(div.addressLargeDivInternal.GetUpperValue())
}

// GetCount returns the count of possible distinct values for this division.
// If not representing multiple values, the count is 1.
//
// For example, a division with the value range of 3-7 has count 5.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (div *IPAddressLargeDivision) GetCount() *big.Int {
	if div == nil {
		return bigZero()
	}
	return div.getCount()
}

// ContainsPrefixBlock returns whether the division range includes
// the block of values for the given prefix length.
func (div *IPAddressLargeDivision) ContainsPrefixBlock(prefixLen BitCount) bool {
	bitCount := div.GetBitCount()

	if prefixLen <= 0 {
		return div.IsFullRange()
	} else if prefixLen >= bitCount {
		return true
	}

	lower, upper := div.getValue(), div.getUpperValue()
	return testBigRange(lower, upper, upper, bitCount, prefixLen)
}

// ContainsSinglePrefixBlock returns whether the division range matches exactly
// the block of values for the given prefix length and
// has just a single prefix for that prefix length.
func (div *IPAddressLargeDivision) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	bitCount := div.GetBitCount()
	prefixLen = checkBitCount(prefixLen, bitCount)
	if prefixLen == 0 {
		return div.IsFullRange()
	}

	lower, upper := div.getValue(), div.getUpperValue()
	return testBigRange(lower, lower, upper, bitCount, prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this division includes the block of all values for that prefix length.
//
// If the entire range can be described in this way, this method returns, the same value as GetPrefixLenForSingleBlock.
//
// This block can have a single prefix or multiple possible prefix values for the returned prefix length.
// To avoid the case of multiple prefix values, use GetPrefixLenForSingleBlock.
//
// If this division represents a single value, a bit count is returned.
func (div *IPAddressLargeDivision) GetMinPrefixLenForBlock() BitCount {
	result := div.GetBitCount()
	if div.IsMultiple() {
		lower, upper := div.getValue(), div.getUpperValue()
		lowerZeros := lower.TrailingZeroBits()
		if lowerZeros != 0 {
			var upperNot big.Int
			upperOnes := upperNot.Not(upper).TrailingZeroBits()
			if upperOnes != 0 {
				prefixedBitCount := BitCount(umin(lowerZeros, upperOnes))
				result -= prefixedBitCount
			}
		}
	}
	return result
}

// GetPrefixLenForSingleBlock returns a prefix length for which there is only one prefix in a given division,
// and the range of values in that division is the same as the block of all values for that prefix.
//
// If the range of division values can be described in this way,
// this method returns, the same value as GetMinPrefixLenForBlock.
//
// If no such prefix length exists, returns nil.
//
// If this division is a single value, this returns the bit count of the segment.
func (div *IPAddressLargeDivision) GetPrefixLenForSingleBlock() PrefixLen {
	prefLen := div.GetMinPrefixLenForBlock()
	bitCount := div.GetBitCount()

	if prefLen == bitCount {
		if !div.IsMultiple() {
			result := PrefixBitCount(prefLen)
			return &result
		}
	} else {
		lower, upper := div.getValue(), div.getUpperValue()
		shift := uint(bitCount - prefLen)
		var one, two big.Int
		if one.Rsh(lower, shift).Cmp(two.Rsh(upper, shift)) == 0 {
			result := PrefixBitCount(prefLen)
			return &result
		}
	}
	return nil
}

func (div *IPAddressLargeDivision) getMaxDigitCount() int {
	var maxValue *BigDivInt
	rad := div.getDefaultTextualRadix()
	bc := div.GetBitCount()
	vals := div.getLargeDivValues()

	if vals == nil {
		maxValue = bigZeroConst()
	} else {
		maxValue = vals.maxValue
	}

	return getBigMaxDigitCount(rad, bc, maxValue)
}

func (div *IPAddressLargeDivision) getDefaultLowerString() string {
	val := div.GetValue()
	rad := div.getBigDefaultTextualRadix()
	mdg := div.getMaxDigitCount()
	return toDefaultBigString(val, rad, false, 0, mdg)
}

func (div *IPAddressLargeDivision) getStringAsLower() string {
	stringer := div.getDefaultLowerString
	if div.divisionValues != nil {
		if cache := div.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}
	return stringer()
}

func (div *IPAddressLargeDivision) isExtendedDigits() bool {
	return isExtendedDigits(div.getDefaultTextualRadix())
}

func (div *IPAddressLargeDivision) getDefaultRangeSeparatorString() string {
	if div.isExtendedDigits() {
		return ExtendedDigitsRangeSeparatorStr
	}
	return RangeSeparatorStr
}

func (div *IPAddressLargeDivision) getDefaultMaskedRangeString() string {
	maxDigitCount := div.getMaxDigitCount()
	radix := div.getBigDefaultTextualRadix()
	return toDefaultBigString(div.getValue(), radix, false, 0, maxDigitCount) +
		div.getDefaultRangeSeparatorString() +
		toDefaultBigString(div.getLargeDivValues().upperValueMasked, radix, false, 0, maxDigitCount)
}

func (div *IPAddressLargeDivision) getDefaultRangeString() string {
	maxDigitCount := div.getMaxDigitCount()
	radix := div.getBigDefaultTextualRadix()
	return toDefaultBigString(div.getValue(), radix, false, 0, maxDigitCount) +
		div.getDefaultRangeSeparatorString() +
		toDefaultBigString(div.getUpperValue(), radix, false, 0, maxDigitCount)
}

// GetString produces a normalized string to represent the segment.
// If the segment is an IP segment string with a CIDR network prefix block for its prefix length,
// the string contains only the lower value of the block range.
// Otherwise, an explicit range will be printed.
// If the segment is not an IP segment,
// the string will be similar to the string output by the GetWildcardString function.
//
// The returned string is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and bit length can be deduced from the context.
// The String method produces strings, which are more appropriate when there is no context.
func (div *IPAddressLargeDivision) GetString() string {
	stringer := func() string {
		if div.IsSinglePrefixBlock() || !div.isMultiple() { //covers the case of single addresses, when there is no prefix or the prefix is the bit count
			return div.getDefaultLowerString()
		} else {
			if div.IsPrefixBlock() {
				return div.getDefaultMaskedRangeString()
			}
			return div.getDefaultRangeString()
		}
	}

	if div.divisionValues != nil {
		if cache := div.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}

	return stringer()
}

// GetWildcardString produces a normalized string to represent the segment,
// favouring wildcards and range characters regardless of any network prefix length.
// The explicit range of a range-valued segment will be printed.
//
// The string returned is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and the bit-length can be deduced from the context.
// The String method produces strings more appropriate when no context is provided.
func (div *IPAddressLargeDivision) GetWildcardString() string {
	stringer := func() string {
		if !div.IsPrefixed() || !div.isMultiple() {
			return div.GetString()
		}
		return div.getDefaultRangeString()
	}

	if div.divisionValues != nil {
		if cache := div.getCache(); cache != nil {
			return cacheStr(&cache.cachedWildcardString, stringer)
		}
	}

	return stringer()
}

func (div *IPAddressLargeDivision) getLowerStringLength(radix int) int {
	return getBigDigitCount(div.getValue(), div.getBigRadix(radix))
}

func (div *IPAddressLargeDivision) getUpperStringLength(radix int) int {
	return getBigDigitCount(div.getUpperValue(), div.getBigRadix(radix))
}

func (div *IPAddressLargeDivision) toDefaultString(val *BigDivInt, radix int, uppercase bool, choppedDigits int) string {
	return toDefaultBigString(val, div.getBigRadix(radix), uppercase, choppedDigits, getBigMaxDigitCount(radix, div.GetBitCount(), div.getLargeDivValues().maxValue))
}

func (div *IPAddressLargeDivision) getLowerString(radix int, uppercase bool, appendable *strings.Builder) {
	appendable.WriteString(div.toDefaultString(div.getValue(), radix, uppercase, 0))
}

func (div *IPAddressLargeDivision) getLowerStringChopped(radix int, choppedDigits int, uppercase bool, appendable *strings.Builder) {
	appendable.WriteString(div.toDefaultString(div.getValue(), radix, uppercase, choppedDigits))
}

func (div *IPAddressLargeDivision) getUpperString(radix int, uppercase bool, appendable *strings.Builder) {
	appendable.WriteString(div.toDefaultString(div.getUpperValue(), radix, uppercase, 0))
}

func (div *IPAddressLargeDivision) getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder) {
	appendable.WriteString(div.toDefaultString(div.getLargeDivValues().upperValueMasked, radix, uppercase, 0))
}

func (div *IPAddressLargeDivision) getSplitLowerString(radix int, choppedDigits int, uppercase bool, splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) {
	var builder strings.Builder
	div.getLowerStringChopped(radix, choppedDigits, uppercase, &builder)
	str := builder.String()
	length := len(str)
	prefLen := len(stringPrefix)

	for i := 0; i < length; i++ {
		if i > 0 {
			appendable.WriteByte(splitDigitSeparator)
		}
		if prefLen > 0 {
			appendable.WriteString(stringPrefix)
		}
		if reverseSplitDigits {
			appendable.WriteByte(str[length-i-1])
		} else {
			appendable.WriteByte(str[i])
		}
	}
}

func (div *IPAddressLargeDivision) getSplitRangeString(
	rangeSeparator string,
	wildcard string,
	radix int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string,
	appendable *strings.Builder) address_error.IncompatibleAddressError {
	var lowerBuilder, upperBuilder strings.Builder
	div.getLowerString(radix, uppercase, &lowerBuilder)
	div.getUpperString(radix, uppercase, &upperBuilder)
	diff := upperBuilder.Len() - lowerBuilder.Len()
	if diff > 0 {
		lowerStr := lowerBuilder.String()
		lowerBuilder.Reset()
		for ; diff > 0; diff-- {
			lowerBuilder.WriteByte('0')
		}
		lowerBuilder.WriteString(lowerStr)
	}

	previousWasFull, nextMustBeFull := true, false
	dig := getDigits(uppercase, radix)
	zeroDigit := dig[0]
	highestDigit := dig[radix-1]
	lowerStr := lowerBuilder.String()
	upperStr := upperBuilder.String()
	length := len(lowerStr)
	prefLen := len(stringPrefix)

	for i := 0; i < length; i++ {
		var index int
		if reverseSplitDigits {
			index = length - i - 1
		} else {
			index = 1
		}

		lower := lowerStr[index]
		upper := upperStr[index]

		if i > 0 {
			appendable.WriteByte(splitDigitSeparator)
		}

		if lower == upper {
			if nextMustBeFull {
				return &incompatibleAddressError{addressError{key: "ipaddress.error.splitMismatch"}}
			}
			if prefLen > 0 {
				appendable.WriteString(stringPrefix)
			}
			appendable.WriteByte(lower)
		} else {
			isFullRange := (lower == zeroDigit) && (upper == highestDigit)
			if isFullRange {
				appendable.WriteString(wildcard)
			} else {
				if nextMustBeFull {
					return &incompatibleAddressError{addressError{key: "ipaddress.error.splitMismatch"}}
				}
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				appendable.WriteByte(lower)
				appendable.WriteString(rangeSeparator)
				appendable.WriteByte(upper)
			}

			if reverseSplitDigits {
				if !previousWasFull {
					return &incompatibleAddressError{addressError{key: "ipaddress.error.splitMismatch"}}
				}
				previousWasFull = isFullRange
			} else {
				nextMustBeFull = true
			}
		}
	}
	return nil
}

func (div *IPAddressLargeDivision) getSplitRangeStringLength(
	rangeSeparator string,
	wildcard string,
	leadingZeroCount int,
	radix int,
	uppercase bool,
	splitDigitSeparator byte,
	reverseSplitDigits bool,
	stringPrefix string) int {
	var lowerBuilder, upperBuilder strings.Builder
	_, _, _ = rangeSeparator, splitDigitSeparator, reverseSplitDigits
	digitsLength := -1
	stringPrefixLength := len(stringPrefix)
	div.getLowerString(radix, uppercase, &lowerBuilder)
	div.getUpperString(radix, uppercase, &upperBuilder)
	dig := getDigits(uppercase, radix)
	zeroDigit := dig[0]
	highestDigit := dig[radix-1]
	remainingAfterLoop := leadingZeroCount
	lowerStr := lowerBuilder.String()
	upperStr := upperBuilder.String()
	upperLength := len(upperStr)
	lowerLength := len(lowerStr)

	for i := 1; i < upperLength; i++ {
		var lower byte
		if i <= lowerLength {
			lower = lowerStr[lowerLength-i]
		}
		upperIndex := upperLength - i
		upper := upperStr[upperIndex]
		isFullRange := (lower == zeroDigit) && (upper == highestDigit)
		if isFullRange {
			digitsLength += len(wildcard) + 1
		} else if lower != upper {
			digitsLength += (stringPrefixLength << 1) + 4 //1 for each digit, 1 for range separator, 1 for split digit separator
		} else {
			//this and any remaining must be singles
			remainingAfterLoop += upperIndex + 1
			break
		}
	}

	if remainingAfterLoop > 0 {
		digitsLength += remainingAfterLoop * (stringPrefixLength + 2) // one for each splitDigitSeparator, 1 for each digit
	}

	return digitsLength
}

func (div *IPAddressLargeDivision) getDigitCount(val *BigDivInt, radix int) int {
	vals := div.divisionValues
	if vals == nil {
		return 1
	}
	var bigRadix *big.Int
	if div.getDefaultTextualRadix() == radix {
		bigRadix = div.getBigDefaultTextualRadix()
	} else {
		bigRadix = big.NewInt(int64(radix))
	}
	return getBigDigitCount(val, bigRadix)
}

func (div *IPAddressLargeDivision) getMaxDigitCountRadix(radix int) int {
	var maxValue *BigDivInt
	bc := div.GetBitCount()
	vals := div.getLargeDivValues()

	if vals == nil {
		maxValue = bigZeroConst()
	} else {
		maxValue = vals.maxValue
	}

	return getBigMaxDigitCount(radix, bc, maxValue)
}

func (div *IPAddressLargeDivision) adjustLeadingZeroCount(leadingZeroCount int, value *BigDivInt, radix int) int {
	if leadingZeroCount < 0 {
		width := div.getDigitCount(value, radix)
		return max(0, div.getMaxDigitCountRadix(radix)-width)
	}
	return leadingZeroCount
}

func (div *IPAddressLargeDivision) adjustLowerLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getValue(), radix)
}

func (div *IPAddressLargeDivision) adjustUpperLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getUpperValue(), radix)
}

type largeDivValues struct {
	bitCount         BitCount
	value            *BigDivInt
	upperValue       *BigDivInt // always points to value when single-valued
	maxValue         *BigDivInt
	upperValueMasked *BigDivInt
	isPrefixBlock    bool // note that isSinglePrefBlock is in the divCache
	isMult           bool
	prefLen          PrefixLen
	cache            divCache
}

func (div *largeDivValues) getBitCount() BitCount {
	return div.bitCount
}

func (div *largeDivValues) getByteCount() int {
	return (int(div.getBitCount()) + 7) >> 3
}

func (div *largeDivValues) getDivisionPrefixLength() PrefixLen {
	return div.prefLen
}

// For internal use.
// Returns a cached value, so it cannot be changed or returned to external callers.
// The only place to clone is the GetValue() and GetUpperValue() methods, which return elsewhere
func (div *largeDivValues) getValue() *BigDivInt {
	return div.value
}

// For internal use.
// Returns a cached value, so it cannot be changed or returned to external callers.
// The only place to clone is the GetValue() and GetUpperValue() methods, which return elsewhere
func (div *largeDivValues) getUpperValue() *BigDivInt {
	return div.upperValue
}

func (div *largeDivValues) includesMax() bool {
	return div.upperValue.Cmp(div.maxValue) == 0
}

func (div *largeDivValues) isMultiple() bool {
	return div.isMult
}

func (div *largeDivValues) calcBytesInternal() ([]byte, []byte) {
	return div.value.Bytes(), div.upperValue.Bytes()
}

func (div *largeDivValues) bytesInternal(upper bool) []byte {
	if upper {
		return div.upperValue.Bytes()
	}
	return div.value.Bytes()
}

func (div *largeDivValues) getCache() *divCache {
	return &div.cache
}

func (div *largeDivValues) getDivisionValue() DivInt {
	return DivInt(div.value.Uint64())
}

func (div *largeDivValues) getUpperDivisionValue() DivInt {
	return DivInt(div.upperValue.Uint64())
}

func (div *largeDivValues) getSegmentValue() SegInt {
	return SegInt(div.value.Uint64())
}

func (div *largeDivValues) getUpperSegmentValue() SegInt {
	return SegInt(div.upperValue.Uint64())
}

func (div *largeDivValues) getAddrType() addrType {
	return zeroType
}

func (div *largeDivValues) includesZero() bool {
	return bigIsZero(div.value)
}

func (div *largeDivValues) getCount() *big.Int {
	var res big.Int
	return res.Sub(div.upperValue, div.value).Add(&res, bigOneConst())
}

func (div *largeDivValues) derivePrefixed(prefLen PrefixLen) divisionValues {
	return newLargeDivValuesUnchecked(div.value, div.upperValue, div.maxValue, div.isMult, prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(DivInt(val), DivInt(upperVal), prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(val, upperVal, prefLen, div.bitCount)
}

func (div *largeDivValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newLargeDivValuesDivIntUnchecked(DivInt(val), DivInt(val), prefLen, div.bitCount)
}

func newLargeDivValuesUnchecked(value, upperValue, maxValue *BigDivInt, isMult bool, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	var isSinglePrefBlock bool
	result := &largeDivValues{
		prefLen:    prefLen,
		bitCount:   bitCount,
		value:      value,
		upperValue: upperValue,
		maxValue:   maxValue,
		isMult:     isMult,
	}
	result.isPrefixBlock, isSinglePrefBlock, result.upperValueMasked =
		setCachedPrefixValues(result.value, result.upperValue, result.maxValue, prefLen, bitCount)

	if isSinglePrefBlock {
		result.cache.isSinglePrefBlock = &trueVal
	} else {
		result.cache.isSinglePrefBlock = &falseVal
	}

	return result
}

func newLargeDivValuesDivIntUnchecked(value, upperValue DivInt, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{
		prefLen:  prefLen,
		bitCount: bitCount,
	}
	val := new(big.Int).SetUint64(uint64(value))

	if value == upperValue {
		result.value, result.upperValue = val, val
	} else {
		result.isMult = true
		result.value, result.upperValue = val, new(big.Int).SetUint64(uint64(upperValue))
	}

	var isSinglePrefBlock bool
	result.maxValue = setMax(result.upperValue, bitCount)
	result.isPrefixBlock, isSinglePrefBlock, result.upperValueMasked =
		setCachedPrefixValues(result.value, result.upperValue, result.maxValue, prefLen, bitCount)

	if isSinglePrefBlock {
		result.cache.isSinglePrefBlock = &trueVal
	} else {
		result.cache.isSinglePrefBlock = &falseVal
	}

	return result
}

func setCachedPrefixValues(value, upperValue, maxValue *BigDivInt, prefLen PrefixLen, bitCount BitCount) (isPrefixBlock, isSinglePrefBlock bool, upperValueMasked *BigDivInt) {
	if prefLen != nil {
		if prefLen.Len() == bitCount {
			isPrefixBlock = true
			isSinglePrefBlock = value == upperValue
			upperValueMasked = upperValue
		} else if prefLen.Len() == 0 {
			valIsZero := bigIsZero(value)
			isFullRange := valIsZero && upperValue == maxValue
			isPrefixBlock = isFullRange
			isSinglePrefBlock = isFullRange
			if valIsZero {
				upperValueMasked = value
			} else {
				upperValueMasked = bigZeroConst()
			}
		} else {
			prefixLen := prefLen.Len()
			isPrefixBlock = testBigRange(value, upperValue, upperValue, bitCount, prefixLen)
			isSinglePrefBlock = testBigRange(value, value, upperValue, bitCount, prefixLen)
			upperValueMasked = setUpperValueMasked(value, upperValue, prefLen, bitCount)
		}
	} else {
		upperValueMasked = upperValue
	}
	return
}

func setUpperValueMasked(value, upperValue *BigDivInt, prefLen PrefixLen, bitCount BitCount) *BigDivInt {
	var networkMask big.Int
	networkMask.Lsh(bigMinusOneConst(), uint(bitCount-prefLen.Len())).And(upperValue, &networkMask)

	if networkMask.Cmp(upperValue) == 0 {
		return upperValue
	} else if networkMask.Cmp(value) == 0 {
		return value
	}

	return &networkMask
}

func testBigRangeMasks(lowerValue, upperValue, finalUpperValue, networkMask, hostMask *BigDivInt) bool {
	var one, two big.Int
	return lowerValue.CmpAbs(one.And(lowerValue, networkMask)) == 0 &&
		finalUpperValue.CmpAbs(two.Or(upperValue, hostMask)) == 0
}

func testBigRange(lowerValue, upperValue, finalUpperValue *BigDivInt, bitCount, divisionPrefixLen BitCount) bool {
	var networkMask, hostMask big.Int

	networkMask.Lsh(bigMinusOneConst(), uint(bitCount-divisionPrefixLen))
	hostMask.Not(&networkMask)

	return testBigRangeMasks(lowerValue, upperValue, finalUpperValue, &networkMask, &hostMask)
}

func setMax(assignedUpper *BigDivInt, bitCount BitCount) (max *BigDivInt) {
	var maxVal big.Int
	max = maxVal.Lsh(bigOneConst(), uint(bitCount)).Sub(&maxVal, bigOneConst())

	if max.CmpAbs(assignedUpper) == 0 {
		max = assignedUpper
	}

	return max
}

func setVal(valueBytes []byte, bitCount BitCount) (assignedValue *BigDivInt, assignedBitCount BitCount, maxVal *BigDivInt) {
	if bitCount < 0 {
		bitCount = 0
	}

	assignedBitCount = bitCount
	maxLen := (bitCount + 7) >> 3

	if len(valueBytes) >= maxLen {
		valueBytes = valueBytes[:maxLen]
	}

	assignedValue = new(big.Int).SetBytes(valueBytes)
	maxVal = setMax(assignedValue, bitCount)
	return
}

func setVals(valueBytes []byte, upperBytes []byte, bitCount BitCount) (assignedValue, assignedUpper *BigDivInt, assignedBitCount BitCount, maxVal *BigDivInt) {
	if bitCount < 0 {
		bitCount = 0
	}

	assignedBitCount = bitCount
	maxLen := (bitCount + 7) >> 3

	if len(valueBytes) >= maxLen || len(upperBytes) >= maxLen {
		extraBits := bitCount & 7
		mask := byte(0xff)
		if extraBits > 0 {
			mask = ^(mask << uint(8-extraBits))
		}
		if len(valueBytes) >= maxLen {
			valueBytes = valueBytes[len(valueBytes)-maxLen:]
			b := valueBytes[0]
			if b&mask != b {
				valueBytes = cloneBytes(valueBytes)
				valueBytes[0] &= mask
			}
		}
		if len(upperBytes) >= maxLen {
			upperBytes = upperBytes[len(upperBytes)-maxLen:]
			b := upperBytes[0]
			if b&mask != b {
				upperBytes = cloneBytes(upperBytes)
				upperBytes[0] &= mask
			}
		}
	}

	assignedValue = new(big.Int).SetBytes(valueBytes)

	if upperBytes == nil || bytes.Compare(valueBytes, upperBytes) == 0 {
		assignedUpper = assignedValue
	} else {
		assignedUpper = new(big.Int).SetBytes(upperBytes)
		cmp := assignedValue.CmpAbs(assignedUpper)
		if cmp == 0 {
			assignedUpper = assignedValue
		} else if cmp > 0 {
			// flip them
			assignedValue, assignedUpper = assignedUpper, assignedValue
		}
	}

	maxVal = setMax(assignedUpper, bitCount)
	return
}

func createLargeAddressDiv(vals divisionValues, defaultRadix int) *IPAddressLargeDivision {
	res := &IPAddressLargeDivision{
		addressLargeDivInternal{
			addressDivisionBase: addressDivisionBase{vals},
		},
	}

	if defaultRadix >= 2 {
		res.defaultRadix = new(big.Int).SetInt64(int64(defaultRadix))
	}

	return res
}

func newLargeDivValue(value []byte, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, bitCount, result.maxValue = setVal(value, bitCount)
	result.bitCount = bitCount
	result.upperValue = result.value
	result.upperValueMasked = result.upperValue
	result.cache.isSinglePrefBlock = &falseVal
	return result
}

func newLargeDivValues(value, upperValue []byte, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, result.upperValue, bitCount, result.maxValue = setVals(value, upperValue, bitCount)
	result.bitCount = bitCount
	result.isMult = result.value != result.upperValue
	result.upperValueMasked = result.upperValue
	result.cache.isSinglePrefBlock = &falseVal
	return result
}

// NewIPAddressLargeDivision creates a division of the given arbitrary bit-length, assigning it the given value.
// If the value's bit length exceeds the given bit length, it is truncated.
func NewIPAddressLargeDivision(val []byte, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivValue(val, bitCount), defaultRadix)
}

// NewIPAddressLargeRangeDivision creates a division of the given arbitrary bit-length, assigning it the given value range.
// If a value's bit length exceeds the given bit length, it is truncated.
func NewIPAddressLargeRangeDivision(val, upperVal []byte, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivValues(val, upperVal, bitCount), defaultRadix)
}

func newLargeDivPrefixedValue(value []byte, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, bitCount, result.maxValue = setVal(value, bitCount)
	result.bitCount = bitCount
	result.upperValue = result.value
	prefLen = checkPrefLen(prefLen, bitCount)
	result.prefLen = prefLen
	if prefLen != nil {
		if result.isPrefixBlock = prefLen.Len() == bitCount; result.isPrefixBlock {
			result.cache.isSinglePrefBlock = &trueVal
			result.upperValueMasked = result.upperValue
		} else {
			result.cache.isSinglePrefBlock = &falseVal
			result.upperValueMasked = setUpperValueMasked(result.value, result.upperValue, prefLen, bitCount)
		}
	} else {
		result.upperValueMasked = result.upperValue
		result.cache.isSinglePrefBlock = &falseVal
	}
	return result
}

func newLargeDivPrefixedValues(value, upperValue []byte, prefLen PrefixLen, bitCount BitCount) *largeDivValues {
	result := &largeDivValues{cache: divCache{}}
	result.value, result.upperValue, bitCount, result.maxValue = setVals(value, upperValue, bitCount)
	result.bitCount = bitCount
	prefLen = checkPrefLen(prefLen, bitCount)
	result.prefLen = prefLen
	result.isMult = result.value != result.upperValue

	var isSinglePrefBlock bool

	result.isPrefixBlock, isSinglePrefBlock, result.upperValueMasked =
		setCachedPrefixValues(result.value, result.upperValue, result.maxValue, prefLen, bitCount)
	if isSinglePrefBlock {
		result.cache.isSinglePrefBlock = &trueVal
	} else {
		result.cache.isSinglePrefBlock = &falseVal
	}
	return result
}

// NewIPAddressLargeRangePrefixDivision creates a division of the given arbitrary bit-length,
// assigning it the given value range and prefix length.
// If a value's bit length exceeds the given bit length, it is truncated.
// If the prefix length exceeds the bit length, it is adjusted to the bit length.
// If the prefix length is negative, it is adjusted to zero.
func NewIPAddressLargeRangePrefixDivision(val, upperVal []byte, prefixLen PrefixLen, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivPrefixedValues(val, upperVal, prefixLen, bitCount), defaultRadix)
}

// NewIPAddressLargePrefixDivision creates a division of the given arbitrary bit-length,
// assigning it the given value and prefix length.
// If the value's bit length exceeds the given bit length, it is truncated.
// If the prefix length exceeds the bit length, it is adjusted to the bit length.
// If the prefix length is negative, it is adjusted to zero.
func NewIPAddressLargePrefixDivision(val []byte, prefixLen PrefixLen, bitCount BitCount, defaultRadix int) *IPAddressLargeDivision {
	return createLargeAddressDiv(newLargeDivPrefixedValue(val, prefixLen, bitCount), defaultRadix)
}
