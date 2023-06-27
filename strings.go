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
