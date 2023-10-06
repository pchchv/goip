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

func (res *boundaryResult) createMask() *IPAddress {
	lowerSection := res.lowerSection
	creator := lowerSection.getAddrType().getIPNetwork().getIPAddressCreator()
	return creator.createAddressInternalFromSection(res.lowerSection, NoZone, nil)
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
	var bytesPerSegment int
	var max SegInt
	var bitsPerSegment BitCount

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

func (parseData *parsedIPAddress) createSegment(
	addressString string,
	version IPVersion,
	val,
	upperVal SegInt,
	useFlags bool,
	parsedSegIndex int,
	segmentPrefixLength PrefixLen,
	creator parsedAddressCreator) (div *AddressDivision, isMultiple bool) {
	parsed := parseData.getAddressParseData()

	if val != upperVal {
		return createRangeSeg(addressString, version, val, upperVal,
			useFlags, parsed, parsedSegIndex,
			segmentPrefixLength, creator), true
	}

	var result *AddressDivision

	if !useFlags {
		result = creator.createSegment(val, val, segmentPrefixLength)
	} else {
		result = creator.createSegmentInternal(
			val,
			segmentPrefixLength,
			addressString,
			val,
			parsed.getFlag(parsedSegIndex, keyStandardStr),
			parsed.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parsed.getIndex(parsedSegIndex, keyLowerStrEndIndex))
	}

	return result, false
}

func (parseData *parsedIPAddress) getType() ipType {
	return fromVersion(parseData.getProviderIPVersion())
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
	var result *AddressDivision
	var lower = stringLower
	var upper = stringUpper

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

// createIPv6Segment creates an IPv6 segment by joining two IPv4 segments.
func createIPv6Segment(value1, value2 SegInt, segmentPrefixLength PrefixLen, creator parsedAddressCreator) *AddressDivision {
	value := (value1 << uint(IPv4BitsPerSegment)) | value2
	return creator.createPrefixSegment(value, segmentPrefixLength)
}

func allocateSegments(segments, originalSegments []*AddressDivision, segmentCount, originalCount int) []*AddressDivision {
	if segments == nil {
		segments = createSegmentArray(segmentCount)
		if originalCount > 0 {
			copy(segments, originalSegments[:originalCount])
		}
	}
	return segments
}

func getPrefixLength(qualifier *parsedHostIdentifierStringQualifier) PrefixLen {
	return qualifier.getEquivalentPrefixLen()
}

// When expanding a set of segments into multiple, it is possible that the new segments do not accurately
// cover the same ranges of values.  This occurs when there is a range in the upper segments and the lower
// segments do not cover the full range (as is the case in the original unexpanded segment).
//
// This does not include compressed 0 segments or compressed '*' segments, as neither can have the issue.
//
// Returns true if the expansion was invalid.
func checkExpandedValues(section *IPAddressSection, start, end int) bool {
	if section != nil && start < end {
		seg := section.GetSegment(start)
		lastWasRange := seg.isMultiple()
		for {
			start++
			seg = section.GetSegment(start)
			if lastWasRange {
				if !seg.IsFullRange() {
					return true
				}
			} else {
				lastWasRange = seg.isMultiple()
			}
			if start >= end {
				break
			}
		}
	}
	return false
}
