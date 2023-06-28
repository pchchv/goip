package goip

import (
	"strings"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

const zeros = "00000000000000000000"

type divStringProvider interface {
	getLowerStringLength(radix int) int
	getUpperStringLength(radix int) int
	getLowerString(radix int, uppercase bool, appendable *strings.Builder)
	getLowerStringChopped(radix int, choppedDigits int, uppercase bool, appendable *strings.Builder)
	getUpperString(radix int, uppercase bool, appendable *strings.Builder)
	getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder)
	getSplitLowerString(radix int, choppedDigits int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder)
	getSplitRangeString(rangeSeparator string, wildcard string, radix int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) address_error.IncompatibleAddressError
	getSplitRangeStringLength(rangeSeparator string, wildcard string, leadingZeroCount int, radix int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string) int
	getRangeDigitCount(radix int) int
	// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
	adjustLowerLeadingZeroCount(leadingZeroCount int, radix int) int
	// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
	adjustUpperLeadingZeroCount(leadingZeroCount int, radix int) int
	getMaxDigitCountRadix(radix int) int
	// returns the default radix for textual representations of addresses (10 for IPv4, 16 for IPv6)
	getDefaultTextualRadix() int // put this in divisionValues perhaps?  or use addrType
	// returns the number of digits for the maximum possible value of the division when using the default radix
	getMaxDigitCount() int
	// simple string using just the lower value and the default radix.
	getDefaultLowerString() string
	// simple string using just the lower and upper values and the default radix, separated by the default range character.
	getDefaultRangeString() string
	// This is the wildcard string that will be used when producing default strings with getString() or getWildcardString().
	// Since no parameters for the string are provided, default parameters are used, but they must be consistent with the address.
	// For example, usually '-' is used as a range separator, but in some cases this character is used to delimit segments.
	// Note that this only applies to the 'default' settings, there are additional string methods that allows to specify these delimiter characters.
	// These methods also need to be aware of the default settings, so that they know when they can fall back on them and when they cannot.
	getDefaultRangeSeparatorString() string
}

// Each segment parameters has settings to write only one type of IP address part of a string segment.
type addressSegmentParams interface {
	getWildcards() address_string.Wildcards
	preferWildcards() bool
	// returns -1 for the number of leading zeros needed to write the max number of characters in the segment,
	// or 0, 1, 2, 3 to indicate the number of leading zeros
	getLeadingZeros(segmentIndex int) int
	getSegmentStrPrefix() string
	getRadix() int
	isUppercase() bool
	isSplitDigits() bool
	hasSeparator() bool
	getSplitDigitSeparator() byte
	isReverseSplitDigits() bool
}

type addressStringParams struct {
	wildcards        address_string.Wildcards
	expandSegments   bool   // whether to expand 1 to 001 for IPv4 or 0001 for IPv6
	segmentStrPrefix string // eg for inet_aton style there is 0x for hex, 0 for octal
	radix            int
	separator        byte // segment separator, and in the case of split digits - the digit separator, default is ' '
	hasSep           bool // whether there is a separator at all
	uppercase        bool // whether to print A or a
	reverse          bool // print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
	splitDigits      bool // in each segment split the digits with a separator so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
	addressLabel     string
	zoneSeparator    string
}

func (params *addressStringParams) getWildcards() address_string.Wildcards {
	return params.wildcards
}

func (params *addressStringParams) preferWildcards() bool {
	return true
}

// getLeadingZeros returns -1 to expand
func (params *addressStringParams) getLeadingZeros(_ int) int {
	if params.expandSegments {
		return -1
	}
	return 0
}

func (params *addressStringParams) getSegmentStrPrefix() string {
	return params.segmentStrPrefix
}

func (params *addressStringParams) getRadix() int {
	return params.radix
}

func (params *addressStringParams) isUppercase() bool {
	return params.uppercase
}

func (params *addressStringParams) isSplitDigits() bool {
	return params.splitDigits
}

func (params *addressStringParams) hasSeparator() bool {
	return params.hasSep
}

func (params *addressStringParams) getSplitDigitSeparator() byte {
	return params.separator
}

func (params *addressStringParams) isReverseSplitDigits() bool {
	return params.reverse
}

func (params *addressStringParams) appendSegment(segmentIndex int, builder *strings.Builder, part AddressDivisionSeries) int {
	div := part.GetGenericDivision(segmentIndex)
	writer := stringWriter{div}
	res, _ := writer.getStandardString(segmentIndex, params, builder)
	return res
}

func (params *addressStringParams) getZoneLength(zone Zone, sep string) int {
	if zone != NoZone {
		return len(zone) + len(sep) // zone separator is one char
	}
	return 0
}

func (params *addressStringParams) getSegmentsStringLength(part AddressDivisionSeries) int {
	count := 0
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		for i := 0; i < divCount; i++ {
			count += params.appendSegment(i, nil, part)
		}
		// Character separator = getSeparator()
		if params.hasSep {
			count += divCount - 1 // the number of separators
		}
	}
	return count
}

func (params *addressStringParams) appendSegments(builder *strings.Builder, part AddressDivisionSeries) *strings.Builder {
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		reverse := params.reverse
		i := 0
		hasSeparator := params.hasSep
		separator := params.separator
		for {
			segIndex := i
			if reverse {
				segIndex = divCount - i - 1
			}
			params.appendSegment(segIndex, builder, part)
			i++
			if i == divCount {
				break
			}
			if hasSeparator {
				builder.WriteByte(separator)
			}
		}
	}
	return builder
}

func (params *addressStringParams) appendLabel(builder *strings.Builder) *strings.Builder {
	str := params.addressLabel
	if str != "" {
		builder.WriteString(str)
	}
	return builder
}

func (params *addressStringParams) getAddressLabelLength() int {
	return len(params.addressLabel)
}

func (params *addressStringParams) appendSingleDivision(seg DivisionType, builder *strings.Builder) int {
	writer := stringWriter{seg}
	if builder == nil {
		result, _ := writer.getStandardString(0, params, nil)
		return result + params.getAddressLabelLength()
	}

	params.appendLabel(builder)
	_, _ = writer.getStandardString(0, params, builder)
	return 0
}

func (params *addressStringParams) getStringLength(addr AddressDivisionSeries) int {
	if addr.GetDivisionCount() > 0 {
		return params.getAddressLabelLength() + params.getSegmentsStringLength(addr)
	}
	return 0
}

type stringWriter struct {
	DivisionType
}

func (writer stringWriter) getLowerStandardString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	count := 0
	stringPrefix := params.getSegmentStrPrefix()
	prefLen := len(stringPrefix)
	if prefLen > 0 {
		if appendable == nil {
			count += prefLen
		} else {
			appendable.WriteString(stringPrefix)
		}
	}
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	if leadingZeroCount != 0 {
		if appendable == nil {
			if leadingZeroCount < 0 {
				return count + writer.getMaxDigitCountRadix(radix)
			} else {
				count += leadingZeroCount
			}
		} else {
			leadingZeroCount = writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
			getLeadingZeros(leadingZeroCount, appendable)
		}
	}
	uppercase := params.isUppercase()
	if radix == writer.getDefaultTextualRadix() {
		// Equivalent to GetString for ip addresses but not GetWildcardString.
		// For other addresses, equivalent to either one.
		str := writer.getStringAsLower()
		if appendable == nil {
			return count + len(str)
		} else if uppercase {
			appendUppercase(str, radix, appendable)
		} else {
			appendable.WriteString(str)
		}
	} else {
		if appendable == nil {
			return count + writer.getLowerStringLength(radix)
		} else {
			writer.getLowerString(radix, uppercase, appendable)
		}
	}
	return 0
}

func (writer stringWriter) adjustRangeDigits(rangeDigits int) int {
	if rangeDigits != 0 {
		// Note: Ranges of type ___ intended to represent 0-fff do not work because the range does not include two-digit or one-digit numbers.
		// It only does if the lower value is 0 and there are more than 1 digits of the range.
		// This is because in this case you can omit all leading zeros.
		// Ranges of type f___ representing f000-ffffff work fine.
		if !writer.IncludesZero() || rangeDigits == 1 {
			return rangeDigits
		}
	}
	return 0
}

func (writer stringWriter) getRangeDigitString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	radix := params.getRadix()
	leadingZerosCount := params.getLeadingZeros(segmentIndex)
	leadingZerosCount = writer.adjustLowerLeadingZeroCount(leadingZerosCount, radix)
	stringPrefix := params.getSegmentStrPrefix()
	prefLen := len(stringPrefix)
	wildcards := params.getWildcards()
	dc := writer.getRangeDigitCount(radix)
	rangeDigits := writer.adjustRangeDigits(dc)
	if appendable == nil {
		return writer.getLowerStringLength(radix) + leadingZerosCount + prefLen
	} else {
		if prefLen > 0 {
			appendable.WriteString(stringPrefix)
		}
		if leadingZerosCount > 0 {
			getLeadingZeros(leadingZerosCount, appendable)
		}
		uppercase := params.isUppercase()
		writer.getLowerStringChopped(radix, rangeDigits, uppercase, appendable)
		for i := 0; i < rangeDigits; i++ {
			appendable.WriteString(wildcards.GetSingleWildcard())
		}
	}
	return 0
}

func (writer stringWriter) getSplitRangeDigitString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	radix := params.getRadix()
	leadingZerosCount := params.getLeadingZeros(segmentIndex)
	leadingZerosCount = writer.adjustLowerLeadingZeroCount(leadingZerosCount, radix)
	stringPrefix := params.getSegmentStrPrefix()
	if appendable != nil {
		wildcards := params.getWildcards()
		dc := writer.getRangeDigitCount(radix)
		rangeDigits := writer.adjustRangeDigits(dc)
		var splitDigitSeparator byte = ' '
		if params.hasSeparator() {
			splitDigitSeparator = params.getSplitDigitSeparator()
		}
		reverseSplitDigits := params.isReverseSplitDigits()
		uppercase := params.isUppercase()
		if reverseSplitDigits {
			getSplitCharStr(rangeDigits, splitDigitSeparator, wildcards.GetSingleWildcard(), stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			writer.getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
			if leadingZerosCount > 0 {
				appendable.WriteByte(splitDigitSeparator)
				getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable)
			}
		} else {
			if leadingZerosCount != 0 {
				getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable)
				appendable.WriteByte(splitDigitSeparator)
			}
			writer.getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			getSplitCharStr(rangeDigits, splitDigitSeparator, wildcards.GetSingleWildcard(), stringPrefix, appendable)
		}
	} else {
		length := writer.getLowerStringLength(radix) + leadingZerosCount
		count := (length << 1) - 1
		prefLen := len(stringPrefix)
		if prefLen > 0 {
			count += length * prefLen
		}
		return count
	}
	return 0
}

func (writer stringWriter) writeSplitRangeString(
	segmentIndex int,
	params addressSegmentParams,
	appendable *strings.Builder) (int, address_error.IncompatibleAddressError) {
	var splitDigitSeparator byte = ' '
	stringPrefix := params.getSegmentStrPrefix()
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	// for split ranges, it is the leading zeros of the upper value that matters
	leadingZeroCount = writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)
	wildcards := params.getWildcards()
	uppercase := params.isUppercase()
	if params.hasSeparator() {
		splitDigitSeparator = params.getSplitDigitSeparator()
	}
	reverseSplitDigits := params.isReverseSplitDigits()
	rangeSeparator := wildcards.GetRangeSeparator()
	if appendable != nil {
		hasLeadingZeros := leadingZeroCount != 0
		if hasLeadingZeros && !reverseSplitDigits {
			getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			hasLeadingZeros = false
		}
		if err := writer.getSplitRangeString(
			rangeSeparator,
			wildcards.GetWildcard(),
			radix,
			uppercase,
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix,
			appendable); err != nil {
			return 0, err
		}
		if hasLeadingZeros {
			appendable.WriteByte(splitDigitSeparator)
			getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
		}
	} else {
		return writer.getSplitRangeStringLength(
			rangeSeparator,
			wildcards.GetWildcard(),
			leadingZeroCount,
			radix,
			uppercase,
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix), nil
	}
	return 0, nil
}

func (writer stringWriter) getRangeStringWithCounts(
	segmentIndex int,
	params addressSegmentParams,
	lowerLeadingZerosCount int,
	upperLeadingZerosCount int,
	maskUpper bool,
	appendable *strings.Builder) int {
	_ = segmentIndex
	stringPrefix := params.getSegmentStrPrefix()
	radix := params.getRadix()
	rangeSeparator := params.getWildcards().GetRangeSeparator()
	uppercase := params.isUppercase()
	return getRangeString(writer.DivisionType, rangeSeparator, lowerLeadingZerosCount, upperLeadingZerosCount, stringPrefix, radix, uppercase, maskUpper, appendable)
}

func (writer stringWriter) getRangeString(
	segmentIndex int, params addressSegmentParams, appendable *strings.Builder) (digitCount int, err address_error.IncompatibleAddressError) {
	splitDigits := params.isSplitDigits()
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	wildcards := params.getWildcards()
	rangeSeparator := wildcards.GetRangeSeparator()
	singleWC := wildcards.GetSingleWildcard()
	rangeDigitCount := 0
	if singleWC != "" {
		rangeDigitCount = writer.getRangeDigitCount(radix)
	}
	lowerLeadingZeroCount := writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
	upperLeadingZeroCount := writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)
	// check the case where we can use the result of getWildcardString, which is cached.
	// It must have the same radix and no chopped digits, and no splitting or reversal of digits.
	// We can insert leading zeros, a string prefix, and different separator string if necessary.
	// Neither can we in the case of a full range (in which case we are here only because we don't need '*')
	if rangeDigitCount == 0 &&
		radix == writer.getDefaultTextualRadix() &&
		!splitDigits &&
		!writer.IsFullRange() {
		str := writer.GetWildcardString()
		rangeSep := writer.getDefaultRangeSeparatorString()
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 &&
			prefLen == 0 &&
			rangeSeparator == rangeSep {
			if appendable == nil {
				return len(str), nil
			}
			appendable.WriteString(str)
			return
		} else {
			if appendable == nil {
				count := len(str) + (len(rangeSeparator) - len(rangeSep)) + lowerLeadingZeroCount + upperLeadingZeroCount
				if prefLen > 0 {
					count += prefLen << 1
				}
				return count, nil
			} else {
				firstEnd := strings.Index(str, rangeSep)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if lowerLeadingZeroCount > 0 {
					getLeadingZeros(lowerLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[0:firstEnd])
				appendable.WriteString(rangeSeparator)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if upperLeadingZeroCount > 0 {
					getLeadingZeros(upperLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[firstEnd+len(rangeSep):])
				return
			}
		}
	}
	// Split digits that result to ranges of digits * are similar to the range of range digits,
	// e.g., f00-fff is both f__ and f.*.*
	// The difference is that for a decimal fraction the last digit of the range is 0-5 (i.e. 255), and for split we only check the full range (0-9),
	// e.g., 200-255 is 2__ but not 2.*.*
	// Another difference: when calculating range digits, the count is 0 if the entire range cannot be written as range digits,
	// e.g., f10-fff has no range digits, but is f.1- f.*.
	if !splitDigits && leadingZeroCount < 0 && appendable == nil {
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		charLength := writer.getMaxDigitCountRadix(radix)
		if rangeDigitCount != 0 {
			count := charLength
			if prefLen > 0 {
				count += prefLen
			}
			return count, nil
		}
		count := charLength << 1
		if prefLen > 0 {
			count += prefLen << 1
		}
		count += len(rangeSeparator)
		return count, nil
	}
	rangeDigitCount = writer.adjustRangeDigits(rangeDigitCount)
	if rangeDigitCount != 0 { // wildcards like _
		if splitDigits {
			return writer.getSplitRangeDigitString(segmentIndex, params, appendable), nil
		} else {
			return writer.getRangeDigitString(segmentIndex, params, appendable), nil
		}
	}
	if splitDigits {
		return writer.writeSplitRangeString(segmentIndex, params, appendable)
	}
	return writer.getRangeStringWithCounts(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, false, appendable), nil
}

func (writer stringWriter) getPrefixAdjustedRangeString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	radix := params.getRadix()
	lowerLeadingZeroCount := writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
	upperLeadingZeroCount := writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)

	// if the wildcards are the same as those used by getString() and there is no character prefix, let's defer getString() so that it is cached
	wildcards := params.getWildcards()
	rangeSeparator := wildcards.GetRangeSeparator()
	rangeDigitCount := 0
	if len(wildcards.GetSingleWildcard()) != 0 {
		rangeDigitCount = writer.getRangeDigitCount(radix)
	}
	// If we can, we reuse the standard string to build this string (it must have the same radix and no chopped digits).
	// We can insert leading zeros, a string prefix and different separator string if necessary.
	// Nor can we in the case of a full range (in which case we are here only because we don't need '*').
	if rangeDigitCount == 0 && radix == writer.getDefaultTextualRadix() && !writer.IsFullRange() {
		// call getString() to cache the result,
		// and we call getString instead of getWildcardString() because it will also mask the length of the segment prefix
		str := writer.GetString()
		rangeSep := writer.getDefaultRangeSeparatorString()
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 && rangeSep == rangeSeparator && prefLen == 0 {
			if appendable == nil {
				return len(str)
			} else {
				if params.isUppercase() {
					appendUppercase(str, radix, appendable)
				} else {
					appendable.WriteString(str)
				}
				return 0
			}
		} else {
			if appendable == nil {
				count := len(str) + (len(rangeSeparator) - len(rangeSep)) +
					lowerLeadingZeroCount + upperLeadingZeroCount
				if prefLen > 0 {
					count += prefLen << 1
				}
				return count
			} else {
				firstEnd := strings.Index(str, rangeSep)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if lowerLeadingZeroCount > 0 {
					getLeadingZeros(lowerLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[0:firstEnd])
				appendable.WriteString(rangeSeparator)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if upperLeadingZeroCount > 0 {
					getLeadingZeros(upperLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[firstEnd+len(rangeSep):])
				return 0
			}
		}
	}

	rangeDigitCount = writer.adjustRangeDigits(rangeDigitCount)
	if leadingZeroCount < 0 && appendable == nil {
		charLength := writer.getMaxDigitCountRadix(radix)
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if rangeDigitCount != 0 {
			count := charLength
			if prefLen > 0 {
				count += prefLen
			}
			return count
		}
		count := charLength << 1
		if prefLen > 0 {
			count += prefLen << 1
		}
		count += len(rangeSeparator)
		return count
	}

	if rangeDigitCount != 0 {
		return writer.getRangeDigitString(segmentIndex, params, appendable)
	}

	return writer.getRangeStringWithCounts(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, true, appendable)
}

// getStandardString creates a string to represent the segment using wildcards and range characters.
// Use this function instead of getWildcardString() if you have a customized wildcard or range separator or if you have a non-zero leadingZeroCount value.
func (writer stringWriter) getStandardString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) (digitCount int, err address_error.IncompatibleAddressError) {
	if !writer.IsMultiple() {
		splitDigits := params.isSplitDigits()
		if splitDigits {
			radix := params.getRadix()
			leadingZeroCount := params.getLeadingZeros(segmentIndex)
			leadingZeroCount = writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
			stringPrefix := params.getSegmentStrPrefix()
			prefLen := len(stringPrefix)
			if appendable == nil {
				var length int
				if leadingZeroCount != 0 {
					if leadingZeroCount < 0 {
						length = writer.getMaxDigitCountRadix(radix)
					} else {
						length = writer.getLowerStringLength(radix) + leadingZeroCount
					}
				} else {
					length = writer.getLowerStringLength(radix)
				}
				count := (length << 1) - 1
				if prefLen > 0 {
					count += length * prefLen
				}
				return count, nil
			} else {
				var splitDigitSeparator byte = ' '
				if params.hasSeparator() {
					splitDigitSeparator = params.getSplitDigitSeparator()
				}
				reverseSplitDigits := params.isReverseSplitDigits()
				uppercase := params.isUppercase()
				if reverseSplitDigits {
					writer.getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
					if leadingZeroCount != 0 {
						appendable.WriteByte(splitDigitSeparator)
						getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
					}
				} else {
					if leadingZeroCount != 0 {
						getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
						appendable.WriteByte(splitDigitSeparator)
					}
					writer.getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
				}
				return
			}
		}
		return writer.getLowerStandardString(segmentIndex, params, appendable), nil
	} else if writer.IsFullRange() {
		wildcard := params.getWildcards().GetWildcard()
		if len(wildcard) > 0 {
			splitDigits := params.isSplitDigits()
			if splitDigits {
				radix := params.getRadix()
				if appendable == nil {
					length := writer.getMaxDigitCountRadix(radix)
					count := length*(len(wildcard)+1) - 1
					return count, nil
				}
				var splitDigitSeparator byte = ' '
				if params.hasSeparator() {
					splitDigitSeparator = params.getSplitDigitSeparator()
				}
				dg := writer.getMaxDigitCountRadix(radix)
				getSplitCharStr(dg, splitDigitSeparator, wildcard, "", appendable)
				return
			}
			return getFullRangeString(wildcard, appendable), nil
		}
	}
	return writer.getRangeString(segmentIndex, params, appendable)
}

func getSplitChar(count int, splitDigitSeparator, character byte, stringPrefix string, builder *strings.Builder) {
	prefLen := len(stringPrefix)
	if count > 0 {
		for {
			if prefLen > 0 {
				builder.WriteString(stringPrefix)
			}
			builder.WriteByte(character)
			count--
			if count <= 0 {
				break
			}
			builder.WriteByte(splitDigitSeparator)
		}
	}
}

func getSplitLeadingZeros(leadingZeroCount int, splitDigitSeparator byte, stringPrefix string, builder *strings.Builder) {
	getSplitChar(leadingZeroCount, splitDigitSeparator, '0', stringPrefix, builder)
}

func getSplitCharStr(count int, splitDigitSeparator byte, characters string, stringPrefix string, builder *strings.Builder) {
	prefLen := len(stringPrefix)
	if count > 0 {
		for {
			if prefLen > 0 {
				builder.WriteString(stringPrefix)
			}
			builder.WriteString(characters)
			count--
			if count <= 0 {
				break
			}
			builder.WriteByte(splitDigitSeparator)
		}
	}
}

func getFullRangeString(wildcard string, appendable *strings.Builder) int {
	if appendable == nil {
		return len(wildcard)
	}
	appendable.WriteString(wildcard)
	return 0
}

func getLeadingZeros(leadingZeroCount int, builder *strings.Builder) {
	if leadingZeroCount > 0 {
		stringArray := zeros
		increment := len(stringArray)
		if leadingZeroCount > increment {
			for leadingZeroCount > increment {
				builder.WriteString(stringArray)
				leadingZeroCount -= increment
			}
		}
		builder.WriteString(stringArray[:leadingZeroCount])
	}
}

func appendUppercase(str string, radix int, appendable *strings.Builder) {
	if radix > 10 {
		for i := 0; i < len(str); i++ {
			c := str[i]
			if c >= 'a' && c <= 'z' {
				c -= byte('a') - byte('A')
			}
			appendable.WriteByte(c)
		}
	} else {
		appendable.WriteString(str)
	}
}
