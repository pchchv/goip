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

func (parseData *parsedIPAddress) createIPv4Sections(doSections, doRangeBoundaries, withUpper bool) (sections sectionResult, boundaries boundaryResult) {
	var segIsMult bool
	isMultiple := false
	isHostMultiple := false
	qualifier := parseData.getQualifier()
	prefLen := getPrefixLength(qualifier)
	mask := parseData.getProviderMask()
	if mask != nil && mask.GetBlockMaskPrefixLen(true) != nil {
		mask = nil //we don't do any masking if the mask is a subnet mask, instead we just map it to the corresponding prefix length
	}

	hasMask := mask != nil
	addrParseData := parseData.getAddressParseData()
	segmentCount := addrParseData.getSegmentCount()
	if hasMask && parseData.maskers == nil {
		parseData.maskers = make([]Masker, segmentCount)
	}

	creator := ipv4Type.getIPNetwork().getIPAddressCreator()
	missingCount := IPv4SegmentCount - segmentCount

	var hostSegments, segments, lowerSegments, upperSegments []*AddressDivision
	if doSections {
		segments = createSegmentArray(IPv4SegmentCount)
	} else if doRangeBoundaries {
		lowerSegments = createSegmentArray(IPv4SegmentCount)
	} else {
		return
	}

	expandedSegments := missingCount <= 0
	expandedStart, expandedEnd := -1, -1
	addressString := parseData.str
	maskedIsDifferent := false

	for i, normalizedSegmentIndex := 0, 0; i < segmentCount; i++ {
		lower := addrParseData.getValue(i, keyLower)
		upper := addrParseData.getValue(i, keyUpper)
		if !expandedSegments {
			//check for any missing segments that we should account for here
			isLastSegment := i == segmentCount-1
			isWildcard := addrParseData.isWildcard(i)
			expandedSegments = isLastSegment
			if !expandedSegments {
				// if we are inet_aton, we must wait for last segment
				// otherwise, we check if we are wildcard and no other wildcard further down
				expandedSegments = !parseData.isInetAtonJoined() && isWildcard
				if expandedSegments {
					for j := i + 1; j < segmentCount; j++ {
						if addrParseData.isWildcard(j) { //another wildcard further down
							expandedSegments = false
							break
						}
					}
				}
			}
			if expandedSegments {
				if isWildcard {
					upper = 0xffffffff >> uint((3-missingCount)<<3)
				} else {
					expandedStart = i
					expandedEnd = i + missingCount
				}
				bits := BitCount(missingCount+1) << ipv4BitsToSegmentBitshift // BitCount(missingCount+1) * IPv4BitsPerSegment
				var maskedLower, maskedUpper uint64
				if hasMask {
					var divMask uint64
					for k := 0; k <= missingCount; k++ {
						divMask = (divMask << uint(IPv4BitsPerSegment)) | uint64(mask.GetSegment(normalizedSegmentIndex+k).GetSegmentValue())
					}
					masker := parseData.maskers[i]
					if masker == nil {
						maxValue := ^(^uint64(0) << uint(bits))
						masker = MaskRange(lower, upper, divMask, maxValue)
						parseData.maskers[i] = masker
					}
					if !masker.IsSequential() && sections.maskError == nil {
						sections.maskError = &incompatibleAddressError{
							addressError: addressError{
								str: maskString(lower, upper, divMask),
								key: "ipaddress.error.maskMismatch",
							},
						}
					}
					maskedLower = masker.GetMaskedLower(lower, divMask)
					maskedUpper = masker.GetMaskedUpper(upper, divMask)
					maskedIsDifferent = maskedIsDifferent || maskedLower != lower || maskedUpper != upper
				} else {
					maskedLower = lower
					maskedUpper = upper
				}
				shift := bits
				count := missingCount
				for count >= 0 { //add the missing segments
					shift -= IPv4BitsPerSegment
					currentPrefix := getSegmentPrefixLength(IPv4BitsPerSegment, prefLen, normalizedSegmentIndex)
					//currentPrefix := getQualifierSegmentPrefixLength(normalizedSegmentIndex, , qualifier)
					hostSegLower := SegInt((lower >> uint(shift)) & IPv4MaxValuePerSegment)
					var hostSegUpper SegInt
					if lower == upper {
						hostSegUpper = hostSegLower
					} else {
						hostSegUpper = SegInt((upper >> uint(shift)) & IPv4MaxValuePerSegment)
					}
					var maskedSegLower, maskedSegUpper SegInt
					if hasMask {
						maskedSegLower = SegInt((maskedLower >> uint(shift)) & IPv4MaxValuePerSegment)
						if maskedLower == maskedUpper {
							maskedSegUpper = maskedSegLower
						} else {
							maskedSegUpper = SegInt((maskedUpper >> uint(shift)) & IPv4MaxValuePerSegment)
						}
					} else {
						maskedSegLower = hostSegLower
						maskedSegUpper = hostSegUpper
					}
					if doSections {
						if maskedIsDifferent || currentPrefix != nil {
							hostSegments = allocateSegments(hostSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
							hostSegments[normalizedSegmentIndex], segIsMult = parseData.createSegment(
								addressString,
								IPv4,
								hostSegLower,
								hostSegUpper,
								false,
								i,
								nil,
								creator)
							isHostMultiple = isHostMultiple || segIsMult
						}
						segments[normalizedSegmentIndex], segIsMult = parseData.createSegment(
							addressString,
							IPv4,
							maskedSegLower,
							maskedSegUpper,
							false,
							i,
							currentPrefix,
							creator)
						isMultiple = isMultiple || segIsMult
					}
					if doRangeBoundaries {
						isRange := maskedSegLower != maskedSegUpper
						if !doSections || isRange {
							if doSections {
								lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
							} // else segments already allocated
							lowerSegments[normalizedSegmentIndex], _ = parseData.createSegment(
								addressString,
								IPv4,
								maskedSegLower,
								maskedSegLower,
								false,
								i,
								currentPrefix,
								creator)
						} else if lowerSegments != nil {
							lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
						}
						if withUpper {
							if isRange {
								upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, normalizedSegmentIndex)
								upperSegments[normalizedSegmentIndex], _ = parseData.createSegment(
									addressString,
									IPv4,
									maskedSegUpper,
									maskedSegUpper,
									false,
									i,
									currentPrefix,
									creator)
							} else if upperSegments != nil {
								upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
							}
						}
					}
					normalizedSegmentIndex++
					count--
				}
				addrParseData.setBitLength(i, bits)
				continue
			} //end handle inet_aton joined segments
		}

		var masker Masker
		unmasked := true
		hostLower, hostUpper := lower, upper

		if hasMask {
			masker = parseData.maskers[i]
			maskInt := uint64(mask.GetSegment(normalizedSegmentIndex).GetSegmentValue())
			if masker == nil {
				masker = MaskRange(lower, upper, maskInt, uint64(creator.getMaxValuePerSegment()))
				parseData.maskers[i] = masker
			}

			if !masker.IsSequential() && sections.maskError == nil {
				sections.maskError = &incompatibleAddressError{
					addressError: addressError{
						str: maskString(lower, upper, maskInt),
						key: "ipaddress.error.maskMismatch",
					},
				}
			}

			lower = masker.GetMaskedLower(lower, maskInt)
			upper = masker.GetMaskedUpper(upper, maskInt)
			unmasked = hostLower == lower && hostUpper == upper
			maskedIsDifferent = maskedIsDifferent || !unmasked
		}

		segmentPrefixLength := getSegmentPrefixLength(IPv4BitsPerSegment, prefLen, normalizedSegmentIndex)

		if doSections {
			if maskedIsDifferent || segmentPrefixLength != nil {
				hostSegments = allocateSegments(hostSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
				hostSegments[normalizedSegmentIndex], segIsMult = parseData.createSegment(
					addressString,
					IPv4,
					SegInt(hostLower),
					SegInt(hostUpper),
					true,
					i,
					nil,
					creator)
				isHostMultiple = isHostMultiple || segIsMult
			}
			segments[normalizedSegmentIndex], segIsMult = parseData.createSegment(
				addressString,
				IPv4,
				SegInt(lower),
				SegInt(upper),
				unmasked,
				i,
				segmentPrefixLength,
				creator)
			isMultiple = isMultiple || segIsMult
		}

		if doRangeBoundaries {
			isRange := lower != upper
			if !doSections || isRange {
				if doSections {
					lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, normalizedSegmentIndex)
				} // else segments already allocated
				lowerSegments[normalizedSegmentIndex], _ = parseData.createSegment(
					addressString,
					IPv4,
					SegInt(lower),
					SegInt(lower),
					false,
					i,
					segmentPrefixLength,
					creator)
			} else if lowerSegments != nil {
				lowerSegments[normalizedSegmentIndex] = segments[normalizedSegmentIndex]
			}

			if withUpper {
				if isRange {
					upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, normalizedSegmentIndex)
					upperSegments[normalizedSegmentIndex], _ = parseData.createSegment(
						addressString,
						IPv4,
						SegInt(upper),
						SegInt(upper),
						false,
						i,
						segmentPrefixLength,
						creator)
				} else if upperSegments != nil {
					upperSegments[normalizedSegmentIndex] = lowerSegments[normalizedSegmentIndex]
				}
			}
		}
		normalizedSegmentIndex++
		addrParseData.setBitLength(i, IPv4BitsPerSegment)
	}
	var result, hostResult *IPAddressSection
	prefLength := getPrefixLength(qualifier)

	if doSections {
		result = creator.createPrefixedSectionInternal(segments, isMultiple, prefLength)
		sections.section = result
		if hostSegments != nil {
			hostResult = creator.createSectionInternal(hostSegments, isHostMultiple).ToIP()
			sections.hostSection = hostResult
			if checkExpandedValues(hostResult, expandedStart, expandedEnd) {
				sections.joinHostError = &incompatibleAddressError{
					addressError{
						str: addressString,
						key: "ipaddress.error.invalid.joined.ranges",
					},
				}
			}
		}

		if checkExpandedValues(result, expandedStart, expandedEnd) {
			sections.joinAddressError = &incompatibleAddressError{addressError{str: addressString, key: "ipaddress.error.invalid.joined.ranges"}}
			if hostResult == nil {
				sections.joinHostError = sections.joinAddressError
			}
		}
	}

	if doRangeBoundaries {
		// if we have a prefix subnet, it is possible our lower and upper boundaries exceed what appears in the parsed address
		prefixLength := getPrefixLength(qualifier)
		isPrefixSub := false
		if prefixLength != nil {
			var lowerSegs, upperSegs []*AddressDivision
			if doSections {
				upperSegs = segments
				lowerSegs = upperSegs
			} else {
				lowerSegs = lowerSegments
				if upperSegments == nil {
					upperSegs = lowerSegments
				} else {
					upperSegs = upperSegments
				}
			}
			isPrefixSub = isPrefixSubnet(
				func(index int) SegInt { return lowerSegs[index].ToSegmentBase().GetSegmentValue() },
				func(index int) SegInt { return upperSegs[index].ToSegmentBase().GetUpperSegmentValue() },
				len(lowerSegs),
				IPv4BytesPerSegment,
				IPv4BitsPerSegment,
				IPv4MaxValuePerSegment,
				prefixLength.bitCount(),
				zerosOnly)
			if isPrefixSub {
				if lowerSegments == nil {
					//allocate lower segments from address segments
					lowerSegments = allocateSegments(lowerSegments, segments, IPv4SegmentCount, IPv4SegmentCount)
				}
				if upperSegments == nil {
					//allocate upper segments from lower segments
					upperSegments = allocateSegments(upperSegments, lowerSegments, IPv4SegmentCount, IPv4SegmentCount)
				}
			}
		}

		if lowerSegments != nil {
			boundaries.lowerSection = creator.createPrefixedSectionInternalSingle(lowerSegments, false, prefLength)
		}

		if upperSegments != nil {
			section := creator.createPrefixedSectionInternal(upperSegments, false, prefLength)
			if isPrefixSub {
				section = section.ToPrefixBlock()
			}
			boundaries.upperSection = section.GetUpper()
		}
	}
	return
}

// this is for parsed addresses which have associated masks
func (parseData *parsedIPAddress) getProviderMask() *IPAddress {
	return parseData.getQualifier().getMaskLower()
}

func (parseData *parsedIPAddress) getProviderNetworkPrefixLen() PrefixLen {
	return parseData.getQualifier().getEquivalentPrefixLen()
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
