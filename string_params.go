package goip

import (
	"strings"

	"github.com/pchchv/goip/address_error"
)

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
