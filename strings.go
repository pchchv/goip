package goip

import "strings"

func getRangeString(
	strProvider divStringProvider,
	rangeSeparator string,
	lowerLeadingZerosCount,
	upperLeadingZerosCount int,
	stringPrefix string,
	radix int,
	uppercase,
	maskUpper bool,
	appendable *strings.Builder) int {

	prefLen := len(stringPrefix)
	hasStringPrefix := prefLen > 0
	if appendable == nil {
		count := lowerLeadingZerosCount + upperLeadingZerosCount +
			strProvider.getLowerStringLength(radix) + strProvider.getUpperStringLength(radix) + len(rangeSeparator)
		if hasStringPrefix {
			count += prefLen << 1
		}
		return count
	} else {
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if lowerLeadingZerosCount > 0 {
			getLeadingZeros(lowerLeadingZerosCount, appendable)
		}
		strProvider.getLowerString(radix, uppercase, appendable)
		appendable.WriteString(rangeSeparator)
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if upperLeadingZerosCount > 0 {
			getLeadingZeros(upperLeadingZerosCount, appendable)
		}
		if maskUpper {
			strProvider.getUpperStringMasked(radix, uppercase, appendable)
		} else {
			strProvider.getUpperString(radix, uppercase, appendable)
		}
	}
	return 0
}

func getDigitCount(value uint64, radix int) int {
	result := 1
	if radix == 16 {
		for {
			value >>= 4
			if value == 0 {
				break
			}
			result++
		}
	} else {
		if radix == 10 {
			if value < 10 {
				return 1
			} else if value < 100 {
				return 2
			} else if value < 1000 {
				return 3
			}
			value /= 1000
			result = 3 // start with 3 in the loop below
		} else if radix == 8 {
			for {
				value >>= 3
				if value == 0 {
					break
				}
				result++
			}
			return result
		}
		rad64 := uint64(radix)
		for {
			value /= rad64
			if value == 0 {
				break
			}
			result++
		}
	}
	return result
}
