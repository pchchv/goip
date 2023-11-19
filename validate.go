package goip

import (
	"math/big"
	"sync/atomic"
	"unsafe"

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
	maskCache            = [3][IPv6BitCount + 1]*maskCreator{}
	loopbackCache        = newEmptyAddrCreator(defaultIPAddrParameters, NoZone)
	maxValues            = [5]uint64{0, IPv4MaxValuePerSegment, 0xffff, 0xffffff, 0xffffffff}
	maxIPv4StringLen     = [9][]int{ //indices are [radix / 2][additionalSegments], and we handle radices 8, 10, 16
		{3, 6, 8, 11},   //no radix supplied we treat as octal, the longest
		{8, 16, 24, 32}, // binary
		{}, {},
		{3, 6, 8, 11},                   //octal: 0377, 0177777, 077777777, 037777777777
		{IPv4SegmentMaxChars, 5, 8, 10}, //decimal: 255, 65535, 16777215, 4294967295
		{}, {},
		{2, 4, 6, 8}, //hex: 0xff, 0xffff, 0xffffff, 0xffffffff
	}
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

func assign3Attributes(start, end int, parseData *addressParseData, parsedSegIndex, leadingZeroStartIndex int) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStartIndex)
	parseData.setIndex(parsedSegIndex,
		keyLowerStrDigitsIndex, uleadingZeroStart,
		keyLowerStrStartIndex, ustart,
		keyLowerStrEndIndex, uend,
		keyUpperStrDigitsIndex, uleadingZeroStart,
		keyUpperStrStartIndex, ustart,
		keyUpperStrEndIndex, uend)
}

func assign4Attributes(start, end int, parseData *addressParseData, parsedSegIndex, radix, leadingZeroStartIndex int) {
	ustart := uint32(start)
	uend := uint32(end)
	uleadingZeroStart := uint32(leadingZeroStartIndex)
	parseData.set7IndexFlags(parsedSegIndex,
		keyLowerRadixIndex, uint32(radix),
		keyLowerStrDigitsIndex, uleadingZeroStart,
		keyLowerStrStartIndex, ustart,
		keyLowerStrEndIndex, uend,
		keyUpperStrDigitsIndex, uleadingZeroStart,
		keyUpperStrStartIndex, ustart,
		keyUpperStrEndIndex, uend)
}

func assignSingleWildcard16(lower uint64, s string, start, end, numSingleWildcards int, parseData *addressParseData, parsedSegIndex, leadingZeroStartIndex int, options address_string_param.AddressStringFormatParams) (err address_error.AddressStringError) {
	digitsEnd := end - numSingleWildcards
	err = checkSingleWildcard(s, start, end, digitsEnd, options)
	if err != nil {
		return
	}

	shift := numSingleWildcards << 2
	lower <<= uint(shift)
	upper := lower | ^(^uint64(0) << uint(shift))
	assign6Attributes2Values1Flags(start, end, leadingZeroStartIndex, start, end, leadingZeroStartIndex,
		parseData, parsedSegIndex, lower, upper, keySingleWildcard)
	return
}

func getMaxIPv4Value(segmentCount int) uint64 {
	return maxValues[segmentCount]
}

func getMaxIPv4StringLength(additionalSegmentsCovered int, radix uint32) int {
	radixHalved := radix >> 1
	if radixHalved < uint32(len(maxIPv4StringLen)) {
		sl := maxIPv4StringLen[radixHalved]
		if additionalSegmentsCovered >= 0 && additionalSegmentsCovered < len(sl) {
			return sl[additionalSegmentsCovered]
		}
	}
	return 0
}

func getStringPrefixCharCount(radix uint32) int {
	switch radix {
	case 10:
		return 0
	case 16:
	case 2:
		return 2
	default:
	}
	return 1
}

func checkSegments(fullAddr string, validationOptions address_string_param.IPAddressStringParams, parseData *ipAddressParseData) address_error.AddressStringError {
	addressParseData := parseData.getAddressParseData()
	segCount := addressParseData.getSegmentCount()
	version := parseData.getProviderIPVersion()
	if version.IsIPv4() {
		missingCount := IPv4SegmentCount - segCount
		ipv4Options := validationOptions.GetIPv4Params()
		hasWildcardSeparator := addressParseData.hasWildcard() && ipv4Options.AllowsWildcardedSeparator()

		// single segments are handled in the parsing code with the allowSingleSegment setting
		if missingCount > 0 && segCount > 1 {
			if ipv4Options.AllowsInetAtonJoinedSegments() {
				parseData.setInetAtonJoined(true)
			} else if !hasWildcardSeparator {
				return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.ipv4.too.few.segments"}}
			}
		}

		// check whether values are too large
		notUnlimitedLength := !ipv4Options.AllowsUnlimitedLeadingZeros()
		hasMissingSegs := missingCount > 0 && ipv4Options.AllowsInetAtonJoinedSegments()
		for i := 0; i < segCount; i++ {
			var max uint64
			if hasMissingSegs && i == segCount-1 {
				max = getMaxIPv4Value(missingCount + 1)
				if addressParseData.isInferredUpperBoundary(i) {
					parseData.setValue(i, keyUpper, max)
					continue
				}
			} else {
				max = IPv4MaxValuePerSegment
			}
			if parseData.getFlag(i, keySingleWildcard) {
				value := parseData.getValue(i, keyLower)
				if value > max {
					return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}}
				}
				if parseData.getValue(i, keyUpper) > max {
					parseData.setValue(i, keyUpper, max)
				}
				if notUnlimitedLength {
					lowerRadix := addressParseData.getRadix(i, keyLowerRadixIndex)
					maxDigitCount := getMaxIPv4StringLength(missingCount, lowerRadix)
					if parseData.getIndex(i, keyLowerStrEndIndex)-parseData.getIndex(i, keyLowerStrDigitsIndex)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
						return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.segment.too.long"}}
					}
				}
			} else {
				value := parseData.getValue(i, keyUpper)
				if value > max {
					return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.ipv4.segment.too.large"}}
				}
				if notUnlimitedLength {
					lowerRadix := addressParseData.getRadix(i, keyLowerRadixIndex)
					maxDigitCount := getMaxIPv4StringLength(missingCount, lowerRadix)
					lowerEndIndex := parseData.getIndex(i, keyLowerStrEndIndex)
					upperEndIndex := parseData.getIndex(i, keyUpperStrEndIndex)
					if lowerEndIndex-parseData.getIndex(i, keyLowerStrDigitsIndex)-getStringPrefixCharCount(lowerRadix) > maxDigitCount {
						return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.segment.too.long"}}
					}
					if lowerEndIndex != upperEndIndex {
						upperRadix := parseData.getRadix(i, keyUpperRadixIndex)
						maxUpperDigitCount := getMaxIPv4StringLength(missingCount, upperRadix)
						if upperEndIndex-parseData.getIndex(i, keyUpperStrDigitsIndex)-getStringPrefixCharCount(upperRadix) > maxUpperDigitCount {
							return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.segment.too.long"}}
						}
					}
				}
			}
		}
	} else {
		totalSegmentCount := segCount
		if parseData.isProvidingMixedIPv6() {
			totalSegmentCount += IPv6MixedReplacedSegmentCount
		}
		hasWildcardSeparator := addressParseData.hasWildcard() && validationOptions.GetIPv6Params().AllowsWildcardedSeparator()
		if !hasWildcardSeparator && totalSegmentCount != 1 && totalSegmentCount < IPv6SegmentCount && !parseData.isCompressed() {
			return &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.too.few.segments"}}
		}
	}
	return nil
}

func checkSingleWildcard(str string, start, end, digitsEnd int, options address_string_param.AddressStringFormatParams) address_error.AddressStringError {
	_ = start
	if !options.GetRangeParams().AllowsSingleWildcard() {
		return &addressStringError{addressError{str: str, key: "ipaddress.error.no.single.wildcard"}}
	}
	for k := digitsEnd; k < end; k++ {
		if str[k] != SegmentSqlSingleWildcard {
			return &addressStringError{addressError{str: str, key: "ipaddress.error.single.wildcard.order"}}
		}
	}
	return nil
}

func getInvalidProvider(validationOptions address_string_param.IPAddressStringParams) ipAddressProvider {
	if validationOptions == defaultIPAddrParameters {
		return invalidProvider
	}
	return &nullProvider{isInvalidVal: true, ipType: invalidType, params: validationOptions}
}

func inferVersion(params address_string_param.IPAddressStringParams) IPVersion {
	if params.AllowsIPv6() {
		if !params.AllowsIPv4() {
			return IPv6
		}
	} else if params.AllowsIPv4() {
		return IPv4
	}
	return IndeterminateIPVersion
}

func getLoopbackCreator(validationOptions address_string_param.IPAddressStringParams, qualifier *parsedHostIdentifierStringQualifier) (res *emptyAddrCreator) {
	zone := qualifier.getZone()
	defaultParams := defaultIPAddrParameters
	if validationOptions == defaultParams && zone == NoZone {
		res = loopbackCache
		if res == nil {
			res = newEmptyAddrCreator(defaultIPAddrParameters, NoZone)
		}
		return
	}
	res = newEmptyAddrCreator(validationOptions, zone)
	return
}

func chooseIPAddressProvider(
	originator HostIdentifierString,
	fullAddr string,
	validationOptions address_string_param.IPAddressStringParams,
	parseData *parsedIPAddress) (res ipAddressProvider, err address_error.AddressStringError) {
	qualifier := parseData.getQualifier()
	version := parseData.getProviderIPVersion()
	if version.IsIndeterminate() {
		version = qualifier.inferVersion(validationOptions) // checks whether a mask, prefix length, or zone makes the version clear
		optionsVersion := inferVersion(validationOptions)   // checks whether IPv4 or IPv6 is disallowed
		if version.IsIndeterminate() {
			version = optionsVersion
			parseData.setVersion(version)
		} else if !optionsVersion.IsIndeterminate() && version != optionsVersion {
			var key string
			if version.IsIPv6() {
				key = "ipaddress.error.ipv6"
			} else {
				key = "ipaddress.error.ipv4"
			}
			err = &addressStringError{addressError{str: fullAddr, key: key}}
			return
		}
		addressParseData := parseData.getAddressParseData()
		if addressParseData.isProvidingEmpty() {
			networkPrefixLength := qualifier.getNetworkPrefixLen()
			if networkPrefixLength != nil {
				if version.IsIndeterminate() {
					version = IPVersion(validationOptions.GetPreferredVersion())
				}
				prefLen := networkPrefixLength.bitCount()
				if validationOptions == defaultIPAddrParameters && prefLen <= IPv6BitCount {
					index := 0
					if version.IsIPv4() {
						index = 1
					} else if version.IsIPv6() {
						index = 2
					}
					creator := (*maskCreator)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&maskCache[index][prefLen]))))
					if creator == nil {
						creator = newMaskCreator(defaultIPAddrParameters, version, networkPrefixLength)
						dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&maskCache[index][prefLen]))
						atomic.StorePointer(dataLoc, unsafe.Pointer(creator))
					}
					res = creator
					return
				}
				res = newMaskCreator(validationOptions, version, networkPrefixLength)
				return
			} else {
				emptyOpt := validationOptions.EmptyStrParsedAs()
				if emptyOpt == address_string_param.LoopbackOption || emptyOpt == address_string_param.ZeroAddressOption {
					result := getLoopbackCreator(validationOptions, qualifier)
					if result != nil {
						res = result
					}
					return
				}

				if validationOptions == defaultIPAddrParameters {
					res = emptyProvider
				} else {
					res = &nullProvider{isEmpty: true, ipType: emptyType, params: validationOptions}
				}
				return
			}
		} else { //isAll
			// Before reaching here, we already checked whether we allow "all", "allowAll".
			if version.IsIndeterminate() && // version not inferred, nor is a particular version disallowed
				validationOptions.AllStrParsedAs() == address_string_param.AllPreferredIPVersion {
				preferredVersion := IPVersion(validationOptions.GetPreferredVersion())
				if !preferredVersion.IsIndeterminate() {
					var formatParams address_string_param.IPAddressStringFormatParams
					if preferredVersion.IsIPv6() {
						formatParams = validationOptions.GetIPv6Params()
					} else {
						formatParams = validationOptions.GetIPv4Params()
					}
					if formatParams.AllowsWildcardedSeparator() {
						version = preferredVersion
					}
				}
			}
			res = newAllCreator(qualifier, version, originator, validationOptions)
			return
		}
	} else {
		if parseData.isZoned() && version.IsIPv4() {
			err = &addressStringError{addressError{str: fullAddr, key: "ipaddress.error.only.ipv6.has.zone"}}
			return
		}
		if err = checkSegments(fullAddr, validationOptions, parseData.getIPAddressParseData()); err == nil {
			res = parseData
		}
	}
	return
}
