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

type stringWriter struct {
	DivisionType
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
