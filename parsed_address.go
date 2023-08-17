package goip

import (
	"strconv"
	"sync"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

type translatedResult struct {
	sections *sectionResult
	rng      *SequentialRange[*IPAddress]
	mask     *IPAddress
}

type boundaryResult struct {
	lowerSection *IPAddressSection
	upperSection *IPAddressSection
}

type sectionResult struct {
	section          *IPAddressSection
	hostSection      *IPAddressSection
	address          *IPAddress
	hostAddress      *IPAddress
	joinHostError    address_error.IncompatibleAddressError
	joinAddressError address_error.IncompatibleAddressError
	mixedError       address_error.IncompatibleAddressError
	maskError        address_error.IncompatibleAddressError
}

func (res *sectionResult) withoutAddressException() bool {
	return res.joinAddressError == nil && res.mixedError == nil && res.maskError == nil
}

type parsedIPAddress struct {
	ipAddressParseData
	ipAddrProvider // provides a few methods like isInvalid
	options        address_string_param.IPAddressStringParams
	originator     HostIdentifierString
	vals           translatedResult
	skipCntains    *bool
	maskers        []Masker
	mixedMaskers   []Masker
	creationLock   sync.Mutex
}

func (parseData *parsedIPAddress) values() *translatedResult {
	return &parseData.vals
}

func (parseData *parsedIPAddress) isProvidingIPAddress() bool {
	return true
}

func (parseData *parsedIPAddress) getParameters() address_string_param.IPAddressStringParams {
	return parseData.options
}

func (parseData *parsedIPAddress) isProvidingMixedIPv6() bool {
	return parseData.ipAddressParseData.isProvidingMixedIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv6() bool {
	return parseData.ipAddressParseData.isProvidingIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv4() bool {
	return parseData.ipAddressParseData.isProvidingIPv4()
}

func (parseData *parsedIPAddress) isProvidingBase85IPv6() bool {
	return parseData.ipAddressParseData.isProvidingBase85IPv6()
}

func (parseData *parsedIPAddress) getProviderIPVersion() IPVersion {
	return parseData.ipAddressParseData.getProviderIPVersion()
}

func (parseData *parsedIPAddress) getIPAddressParseData() *ipAddressParseData {
	return &parseData.ipAddressParseData
}

func (parseData *parsedIPAddress) getVersionedAddress(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
	thisVersion := parseData.getProviderIPVersion()

	if version != thisVersion {
		return nil, nil
	}

	return parseData.getProviderAddress()
}

// isPrefixSubnet is not called with parsing data from inetAton or single-segment strings, so casting to int is acceptable.
// This is only for addresses with the standard segment counts, although compressed addresses are allowed.
func (parseData *parsedIPAddress) isPrefixSubnet(networkPrefixLength BitCount) bool {
	var (
		bytesPerSegment int
		max             SegInt
		bitsPerSegment  BitCount
	)

	if parseData.isProvidingIPv4() {
		bytesPerSegment = IPv4BytesPerSegment
		bitsPerSegment = IPv4BitsPerSegment
		max = IPv4MaxValuePerSegment
	} else {
		bytesPerSegment = IPv6BytesPerSegment
		bitsPerSegment = IPv6BitsPerSegment
		max = IPv6MaxValuePerSegment
	}

	addressParseData := parseData.getAddressParseData()
	segmentCount := addressParseData.getSegmentCount()

	if parseData.isCompressed() {
		compressedCount := IPv6SegmentCount - segmentCount
		compressedIndex := addressParseData.getConsecutiveSeparatorSegmentIndex()
		return isPrefixSubnet(
			func(segmentIndex int) SegInt {
				if segmentIndex >= compressedIndex {
					if segmentIndex-compressedIndex < compressedCount {
						return 0
					}
					segmentIndex -= compressedCount
				}
				return SegInt(parseData.getValue(segmentIndex, keyLower))
			},
			func(segmentIndex int) SegInt {
				if segmentIndex >= compressedIndex {
					if segmentIndex-compressedIndex < compressedCount {
						return 0
					}
					segmentIndex -= compressedCount
				}
				return SegInt(parseData.getValue(segmentIndex, keyUpper))
			},
			segmentCount+compressedCount,
			bytesPerSegment,
			bitsPerSegment,
			max,
			networkPrefixLength,
			zerosOrFullRange)
	}

	return isPrefixSubnet(
		func(segmentIndex int) SegInt {
			return SegInt(parseData.getValue(segmentIndex, keyLower))
		},
		func(segmentIndex int) SegInt {
			return SegInt(parseData.getValue(segmentIndex, keyUpper))
		},
		segmentCount,
		bytesPerSegment,
		bitsPerSegment,
		max,
		networkPrefixLength,
		zerosOrFullRange)
}

func createRangeSeg(
	addressString string,
	_ IPVersion,
	stringLower,
	stringUpper SegInt,
	useFlags bool,
	parseData *addressParseData,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator parsedAddressCreator) *AddressDivision {
	var (
		result *AddressDivision
		lower  = stringLower
		upper  = stringUpper
	)

	if !useFlags {
		result = creator.createSegment(lower, upper, segmentPrefixLength)
	} else {
		result = creator.createRangeSegmentInternal(
			lower,
			upper,
			segmentPrefixLength,
			addressString,
			stringLower,
			stringUpper,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getFlag(parsedSegIndex, keyStandardRangeStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex),
			parseData.getIndex(parsedSegIndex, keyUpperStrEndIndex))
	}

	return result
}

func maskString(lower, upper, maskInt uint64) string {
	return strconv.FormatUint(lower, 10) + "-" + strconv.FormatUint(upper, 10) + " /" + strconv.FormatUint(maskInt, 10)
}

func createFullRangeSegment(
	version IPVersion,
	stringLower,
	stringUpper SegInt,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	mask *SegInt,
	creator parsedAddressCreator) (result, hostResult, lower, upper *AddressDivision, err address_error.IncompatibleAddressError) {
	var maskedLower, maskedUpper SegInt
	maskedIsDifferent := false
	hasMask := mask != nil
	if hasMask {
		maskInt := DivInt(*mask)
		lstringLower := uint64(stringLower)
		lstringUpper := uint64(stringUpper)
		masker := MaskRange(lstringLower, lstringUpper, maskInt, uint64(creator.getMaxValuePerSegment()))
		if !masker.IsSequential() {
			err = &incompatibleAddressError{
				addressError{
					str: maskString(lstringLower, lstringUpper, maskInt),
					key: "ipaddress.error.maskMismatch",
				},
			}
		}
		maskedLower = SegInt(masker.GetMaskedLower(lstringLower, maskInt))
		maskedUpper = SegInt(masker.GetMaskedUpper(lstringUpper, maskInt))
		maskedIsDifferent = maskedLower != stringLower || maskedUpper != stringUpper
	} else {
		maskedLower = stringLower
		maskedUpper = stringUpper
	}

	result = createRangeSeg("", version, maskedLower, maskedUpper,
		false, nil, parsedSegIndex, segmentPrefixLength, creator)

	if maskedIsDifferent || segmentPrefixLength != nil {
		hostResult = createRangeSeg("", version, stringLower, stringUpper,
			false, nil, parsedSegIndex, nil, creator)
	} else {
		hostResult = result
	}

	if maskedLower == maskedUpper {
		lower = result
		upper = result
	} else {
		lower = createRangeSeg("", version, maskedLower, maskedLower,
			false, nil, parsedSegIndex, segmentPrefixLength, creator)
		upper = createRangeSeg("", version, maskedUpper, maskedUpper,
			false, nil, parsedSegIndex, segmentPrefixLength, creator)
	}

	return
}
