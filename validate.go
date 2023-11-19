package goip

import (
	"math/big"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

const (
	longSize                           = 64
	longHexDigits                      = longSize >> 2
	longBinaryDigits                   = longSize
	maxWildcards                       = ipv6Base85SingleSegmentDigitCount - 1 // 20 wildcards is equivalent to a base 85 address
	maxHostLength                      = 253
	maxLabelLength                     = 63
	maxHostSegments                    = 127
	macSingleSegmentDigitCount         = 12
	macDoubleSegmentDigitCount         = 6
	macExtendedSingleSegmentDigitCount = 16
	macExtendedDoubleSegmentDigitCount = 10
	ipv6SingleSegmentDigitCount        = 32
	ipv6BinarySingleSegmentDigitCount  = 128
	ipv4BinarySingleSegmentDigitCount  = 32
	ipv6Base85SingleSegmentDigitCount  = 20
	ipv4SingleSegmentOctalDigitCount   = 11
)

var (
	chars, extendedChars = createChars()
	base85Powers         = createBase85Powers()
)

type strValidator struct{}

func createChars() (chars [int('z') + 1]byte, extendedChars [int('~') + 1]byte) {
	i := byte(1)
	for c := '1'; i < 10; i, c = i+1, c+1 {
		chars[c] = i
	}

	for c, c2 := 'a', 'A'; i < 26; i, c, c2 = i+1, c+1, c2+1 {
		chars[c] = i
		chars[c2] = i
	}

	var extendedDigits = []byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
		'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
		'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-',
		';', '<', '=', '>', '?', '@', '^', '_', '`', '{', '|', '}',
		'~'}
	extLen := byte(len(extendedDigits))

	for i = 0; i < extLen; i++ {
		c := extendedDigits[i]
		extendedChars[c] = i
	}
	return
}

func isSingleSegmentIPv6(str string, totalDigits int, isRange bool, frontTotalDigits int,
	ipv6SpecificOptions address_string_param.IPv6AddressStringParams) (isSingle bool, err address_error.AddressStringError) {
	backIsIpv6 := totalDigits == ipv6SingleSegmentDigitCount || // 32 hex chars with or without 0x
		(ipv6SpecificOptions.AllowsBinary() && totalDigits == ipv6BinarySingleSegmentDigitCount+2) || // 128 binary chars with 0b
		(isRange && totalDigits == 0 && (frontTotalDigits == ipv6SingleSegmentDigitCount ||
			(ipv6SpecificOptions.AllowsBinary() && frontTotalDigits == ipv6BinarySingleSegmentDigitCount+2)))
	if backIsIpv6 && isRange && totalDigits != 0 {
		frontIsIpv6 := frontTotalDigits == ipv6SingleSegmentDigitCount ||
			(ipv6SpecificOptions.AllowsBinary() && frontTotalDigits == ipv6BinarySingleSegmentDigitCount+2) ||
			frontTotalDigits == 0
		if !frontIsIpv6 {
			err = &addressStringError{addressError{str: str, key: "ipaddress.error.too.few.segments.digit.count"}}
			return
		}
	}
	isSingle = backIsIpv6
	return
}

// When checking for binary single segment, it is necessary to check the exact number of digits for IPv4.
// This is because in IPv6 there is ambiguity between hexadecimal 32 characters starting with 0b and 0b before 30 binary characters.
// Therefore, for IPv4, we must avoid 0b before 30 binary characters.
// It is necessary to require 0b before 32 binary characters.
// This only applies to single segment.
// For segmented IPv4 there is no ambiguity, and we allow binary segments of different lengths as for inetAton.

func isSingleSegmentIPv4(str string, nonZeroDigits, totalDigits int, isRange bool, frontNonZeroDigits, frontTotalDigits int,
	ipv4SpecificOptions address_string_param.IPv4AddressStringParams) (isSingle bool, err address_error.AddressStringError) {
	backIsIpv4 := nonZeroDigits <= ipv4SingleSegmentOctalDigitCount ||
		(ipv4SpecificOptions.AllowsBinary() && totalDigits == ipv4BinarySingleSegmentDigitCount+2) ||
		(isRange && totalDigits == 0 && (frontTotalDigits <= ipv4SingleSegmentOctalDigitCount ||
			(ipv4SpecificOptions.AllowsBinary() && frontTotalDigits == ipv4BinarySingleSegmentDigitCount+2)))
	if backIsIpv4 && isRange && totalDigits != 0 {
		frontIsIpv4 := frontNonZeroDigits <= ipv4SingleSegmentOctalDigitCount ||
			(ipv4SpecificOptions.AllowsBinary() && frontTotalDigits == ipv4BinarySingleSegmentDigitCount+2) ||
			frontTotalDigits == 0
		if !frontIsIpv4 {
			err = &addressStringError{addressError{str: str, key: "ipaddress.error.too.few.segments.digit.count"}}
			return
		}
	}
	isSingle = backIsIpv4
	return
}

func createBase85Powers() []big.Int {
	res := make([]big.Int, 10)
	eightyFive := big.NewInt(85)
	res[0].SetUint64(1)
	for i := 1; i < len(res); i++ {
		res[i].Mul(&res[i-1], eightyFive)
	}
	return res
}

func parse85(s string, start, end int) *big.Int {
	var last bool
	var result big.Int
	charArray := extendedChars
	for {
		var partialEnd, power int
		left := end - start
		if last = left <= 9; last {
			partialEnd = end
			power = left
		} else {
			partialEnd = start + 9
			power = 9
		}
		var partialResult = uint64(charArray[s[start]])
		for start++; start < partialEnd; start++ {
			next := charArray[s[start]]
			partialResult = (partialResult * 85) + uint64(next)
		}
		result.Mul(&result, &base85Powers[power]).Add(&result, new(big.Int).SetUint64(partialResult))
		if last {
			break
		}
	}
	return &result
}

func assign3Attributes2Values1Flags(start, end, leadingZeroStart int, parseData *addressParseData, parsedSegIndex int, value, extendedValue uint64, flags uint32) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStart)
	parseData.set7Index4ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyLowerStrDigitsIndex, uleadingZeroStart,
		keyLowerStrStartIndex, ustart,
		keyLowerStrEndIndex, uend,
		keyUpperStrDigitsIndex, uleadingZeroStart,
		keyUpperStrStartIndex, ustart,
		keyUpperStrEndIndex, uend,
		keyLower, value,
		keyExtendedLower, extendedValue,
		keyUpper, value,
		keyExtendedUpper, extendedValue)
}

func assign3Attributes1Values1Flags(start, end, leadingZeroStart int, parseData *addressParseData, parsedSegIndex int, value uint64, flags uint32) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStart)
	parseData.set7Index2ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyUpperStrDigitsIndex, uleadingZeroStart,
		keyLowerStrDigitsIndex, uleadingZeroStart,
		keyUpperStrStartIndex, ustart,
		keyLowerStrStartIndex, ustart,
		keyUpperStrEndIndex, uend,
		keyLowerStrEndIndex, uend,
		keyLower, value,
		keyUpper, value)
}

func assign7Attributes4Values1Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *addressParseData, parsedSegIndex int, frontValue, frontExtendedValue, value, extendedValue uint64, flags uint32, upperRadix uint32) {
	parseData.set8Index4ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyLowerStrDigitsIndex, uint32(frontLeadingZeroStartIndex),
		keyLowerStrStartIndex, uint32(frontStart),
		keyLowerStrEndIndex, uint32(frontEnd),
		keyUpperRadixIndex, uint32(upperRadix),
		keyUpperStrDigitsIndex, uint32(leadingZeroStartIndex),
		keyUpperStrStartIndex, uint32(start),
		keyUpperStrEndIndex, uint32(end),
		keyLower, frontValue,
		keyExtendedLower, frontExtendedValue,
		keyUpper, value,
		keyExtendedUpper, extendedValue)
}

func assign6Attributes4Values1Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *addressParseData, parsedSegIndex int, frontValue, frontExtendedValue, value, extendedValue uint64, flags uint32) {
	parseData.set7Index4ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyLowerStrDigitsIndex, uint32(frontLeadingZeroStartIndex),
		keyLowerStrStartIndex, uint32(frontStart),
		keyLowerStrEndIndex, uint32(frontEnd),
		keyUpperStrDigitsIndex, uint32(leadingZeroStartIndex),
		keyUpperStrStartIndex, uint32(start),
		keyUpperStrEndIndex, uint32(end),
		keyLower, frontValue,
		keyExtendedLower, frontExtendedValue,
		keyUpper, value,
		keyExtendedUpper, extendedValue)
}

func assign6Attributes2Values1Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *addressParseData, parsedSegIndex int, frontValue, value uint64, flags uint32) {
	parseData.set7Index2ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyLowerStrDigitsIndex, uint32(frontLeadingZeroStartIndex),
		keyLowerStrStartIndex, uint32(frontStart),
		keyLowerStrEndIndex, uint32(frontEnd),
		keyUpperStrDigitsIndex, uint32(leadingZeroStartIndex),
		keyUpperStrStartIndex, uint32(start),
		keyUpperStrEndIndex, uint32(end),
		keyLower, frontValue,
		keyUpper, value)
}

func assign6Attributes2Values2Flags(frontStart, frontEnd, frontLeadingZeroStartIndex, start, end, leadingZeroStartIndex int,
	parseData *addressParseData, parsedSegIndex int, frontValue, value uint64, flags /* includes lower radix */ uint32, upperRadix uint32) {
	parseData.set8Index2ValuesFlags(parsedSegIndex,
		flagsIndex, flags,
		keyLowerStrDigitsIndex, uint32(frontLeadingZeroStartIndex),
		keyLowerStrStartIndex, uint32(frontStart),
		keyLowerStrEndIndex, uint32(frontEnd),
		keyUpperRadixIndex, uint32(upperRadix),
		keyUpperStrDigitsIndex, uint32(leadingZeroStartIndex),
		keyUpperStrStartIndex, uint32(start),
		keyUpperStrEndIndex, uint32(end),
		keyLower, frontValue,
		keyUpper, value)
}
