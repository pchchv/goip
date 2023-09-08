package goip

import (
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

var zeroSection = createSection(zeroDivs, nil, zeroType)

type addressSectionInternal struct {
	addressDivisionGroupingInternal
}

// GetSegmentCount returns the segment count.
func (section *addressSectionInternal) GetSegmentCount() int {
	return section.GetDivisionCount()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.getDivision(index).ToSegmentBase()
}

// Bytes returns the lowest individual address section in this address section as a byte slice.
func (section *addressSectionInternal) Bytes() []byte {
	return section.addressDivisionGroupingInternal.Bytes()
}

// GetBitsPerSegment returns the number of bits comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *addressSectionInternal) GetBitsPerSegment() BitCount {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BitsPerSegment
	} else if addrType.isIPv6() {
		return IPv6BitsPerSegment
	} else if addrType.isMAC() {
		return MACBitsPerSegment
	}

	if section.GetDivisionCount() == 0 {
		return 0
	}

	return section.getDivision(0).GetBitCount()
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *addressSectionInternal) GetBytesPerSegment() int {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BytesPerSegment
	} else if addrType.isIPv6() {
		return IPv6BytesPerSegment
	} else if addrType.isMAC() {
		return MACBytesPerSegment
	}

	if section.GetDivisionCount() == 0 {
		return 0
	}

	return section.getDivision(0).GetByteCount()
}

func (section *addressSectionInternal) toAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *addressSectionInternal) toIPAddressSection() *IPAddressSection {
	return section.toAddressSection().ToIP()
}

func (section *addressSectionInternal) toIPv4AddressSection() *IPv4AddressSection {
	return section.toAddressSection().ToIPv4()
}

func (section *addressSectionInternal) toIPv6AddressSection() *IPv6AddressSection {
	return section.toAddressSection().ToIPv6()
}

func (section *addressSectionInternal) toMACAddressSection() *MACAddressSection {
	return section.toAddressSection().ToMAC()
}

func (section *addressSectionInternal) toPrefixBlock() *AddressSection {
	prefixLength := section.getPrefixLen()
	if prefixLength == nil {
		return section.toAddressSection()
	}

	return section.toPrefixBlockLen(prefixLength.bitCount())
}

func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	prefLen = checkSubnet(section, prefLen)
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section.toAddressSection()
	}

	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.getPrefixLen()
	prefixMatches := existingPrefixLength != nil && existingPrefixLength.bitCount() == prefLen
	if prefixMatches {
		prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		if prefixedSegmentIndex >= segCount {
			return section.toAddressSection()
		}
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex).bitCount()
		seg := section.GetSegment(prefixedSegmentIndex)
		if seg.containsPrefixBlock(segPrefLength) {
			i := prefixedSegmentIndex + 1
			for ; i < segCount; i++ {
				seg = section.GetSegment(i)
				if !seg.IsFullRange() {
					break
				}
			}
			if i == segCount {
				return section.toAddressSection()
			}
		}
	}

	prefixedSegmentIndex := 0
	newSegs := createSegmentArray(segCount)
	if prefLen > 0 {
		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		section.copySubDivisions(0, prefixedSegmentIndex, newSegs)
	}

	for i := prefixedSegmentIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
		oldSeg := section.getDivision(i)
		newSegs[i] = oldSeg.toPrefixedNetworkDivision(segPrefLength)
	}

	return createSectionMultiple(newSegs, cacheBitCount(prefLen), section.getAddrType(), section.isMultiple() || prefLen < section.GetBitCount())
}

func (section *addressSectionInternal) initImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			minPref := segment.GetMinPrefixLenForBlock()
			if minPref > 0 {
				if minPref != bitsPerSegment || i != segCount-1 {
					section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
				}
				return
			}
		}
		section.prefixLength = cacheBitCount(0)
	}
}

func (section *addressSectionInternal) initMultAndImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isMultiple := false
		isBlock := true
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			if isBlock {
				minPref := segment.GetMinPrefixLenForBlock()
				if minPref > 0 {
					if minPref != bitsPerSegment || i != segCount-1 {
						section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
					}
					isBlock = false
					if isMultiple { // nothing left to do
						return
					}
				}
			}
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
				if !isBlock { // nothing left to do
					return
				}
			}
		}
		if isBlock {
			section.prefixLength = cacheBitCount(0)
		}
	}
}

// GetLower returns a segment representing just the lowest value in the range, which will be the same segment if it represents a single value.
func (seg *addressSegmentInternal) GetLower() *AddressSegment {
	return seg.getLower()
}

// GetUpper returns a segment representing just the highest value in the range, which will be the same segment if it represents a single value.
func (seg *addressSegmentInternal) GetUpper() *AddressSegment {
	return seg.getUpper()
}

func (section *addressSectionInternal) createLowestHighestSections() (lower, upper *AddressSection) {
	var highSegs []*AddressDivision
	segmentCount := section.GetSegmentCount()
	lowSegs := createSegmentArray(segmentCount)

	if section.isMultiple() {
		highSegs = createSegmentArray(segmentCount)
	}

	for i := 0; i < segmentCount; i++ {
		seg := section.GetSegment(i)
		lowSegs[i] = seg.GetLower().ToDiv()
		if highSegs != nil {
			highSegs[i] = seg.GetUpper().ToDiv()
		}
	}

	lower = deriveAddressSection(section.toAddressSection(), lowSegs)

	if highSegs == nil {
		upper = lower
	} else {
		upper = deriveAddressSection(section.toAddressSection(), highSegs)
	}

	return
}

func (section *addressSectionInternal) getLowestHighestSections() (lower, upper *AddressSection) {
	if !section.isMultiple() {
		lower = section.toAddressSection()
		upper = lower
		return
	}

	cache := section.cache
	if cache == nil {
		return section.createLowestHighestSections()
	}

	cached := (*groupingCache)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.sectionCache))))
	if cached == nil {
		cached = &groupingCache{}
		cached.lower, cached.upper = section.createLowestHighestSections()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.sectionCache))
		atomicStorePointer(dataLoc, unsafe.Pointer(cached))
	}

	lower = cached.lower
	upper = cached.upper

	return
}

func (section *addressSectionInternal) getLower() *AddressSection {
	lower, _ := section.getLowestHighestSections()
	return lower
}

func (section *addressSectionInternal) getUpper() *AddressSection {
	_, upper := section.getLowestHighestSections()
	return upper
}

// AddressSection is an address section containing a certain number of consecutive segments.
// It is a series of individual address segments.
// Each segment has the same bit length.
// Each address is backed by an address section that contains all address segments.
//
// AddressSection instances are immutable.
// This also makes them concurrency-safe.
//
// Most operations that can be performed on Address instances can also be performed on AddressSection instances, and vice versa.
type AddressSection struct {
	addressSectionInternal
}

// IsMultiple returns whether this section represents multiple values.
func (section *AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

// ToDivGrouping converts to AddressDivisionGrouping, a polymorphic type used with all address sections and divisional groupings.
// The conversion can then be reversed using ToSectionBase.
// ToDivGrouping can be called with a nil receiver, allowing this method to be used in a chain with methods that can return a nil pointer.
func (section *AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
}

// ToSectionBase is an identity method.
// ToSectionBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToSectionBase() *AddressSection {
	return section
}

// IsIPv4 returns true if this address section originated as an IPv4 section.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (section *AddressSection) IsIPv4() bool {
	return section != nil && section.matchesIPv4SectionType()
}

// IsIPv6 returns true if this address section originated as an IPv6 section.
// If so, use ToIPv6 to convert back to the IPv6-specific type.
func (section *AddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6SectionType()
}

// IsMAC returns true if this address section originated as a MAC section.
// If so, use ToMAC to convert back to the MAC-specific type.
func (section *AddressSection) IsMAC() bool {
	return section != nil && section.matchesMACSectionType()
}

// IsIP returns true if this address section originated as an IPv4 or IPv6 section, or a zero-length IP section.
// If so, use ToIP to convert back to the IP-specific type.
func (section *AddressSection) IsIP() bool {
	return section != nil && section.matchesIPSectionType()
}

// ToIP converts to an IPAddressSection if this address section originated as an IPv4 or IPv6 section,
// or an implicitly zero-valued IP section.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIP() *IPAddressSection {
	if section.IsIP() {
		return (*IPAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToIPv4 converts to an IPv4AddressSection if this section originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIPv4() *IPv4AddressSection {
	if section.IsIPv4() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToIPv6 converts to an IPv6AddressSection if this section originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIPv6() *IPv6AddressSection {
	if section.IsIPv6() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToMAC converts to a MACAddressSection if this section originated as a MAC section.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToMAC() *MACAddressSection {
	if section.IsMAC() {
		return (*MACAddressSection)(section)
	}
	return nil
}

// IsAdaptiveZero returns true if the division grouping was originally created as an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// meaning it was not constructed using a constructor function.
// Such a grouping, which has no divisions or segments, is convertible to an implicitly zero-valued grouping of any type or version, whether IPv6, IPv4, MAC, or other.
// In other words, when a section or grouping is the zero-value, then it is equivalent and convertible to the zero value of any other section or grouping type.
func (section *AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

// ToPrefixBlock returns the section with the same prefix as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
//
// If this section has no prefix, this section is returned.
func (section *AddressSection) ToPrefixBlock() *AddressSection {
	return section.toPrefixBlock()
}

// ToPrefixBlockLen returns the section with the same prefix of the given length as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
func (section *AddressSection) ToPrefixBlockLen(prefLen BitCount) *AddressSection {
	return section.toPrefixBlockLen(prefLen)
}

// GetLower returns the section in the range with the lowest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.2.4.5" is returned.
func (section *AddressSection) GetLower() *AddressSection {
	return section.getLower()
}

// GetUpper returns the section in the range with the highest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.3.4.6" is returned.
func (section *AddressSection) GetUpper() *AddressSection {
	return section.getUpper()
}

func assignStringCache(section *addressDivisionGroupingBase, addrType addrType) {
	stringCache := &section.cache.stringCache
	if addrType.isIPv4() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv4StringCache = &ipv4StringCache{}
	} else if addrType.isIPv6() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv6StringCache = &ipv6StringCache{}
	} else if addrType.isMAC() {
		stringCache.macStringCache = &macStringCache{}
	}
}

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressSection {
	sect := &AddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions:    standardDivArray(segments),
					prefixLength: prefixLength,
					addrType:     addrType,
					cache:        &valueCache{},
				},
			},
		},
	}
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

func createDivisionsFromSegs(
	segProvider func(index int) *IPAddressSegment,
	segCount int,
	bitsToSegmentShift uint,
	bitsPerSegment BitCount,
	bytesPerSegment int,
	maxValuePerSegment SegInt,
	zeroSeg, zeroSegZeroPrefix, zeroSegPrefixBlock *IPAddressSegment,
	assignedPrefLen PrefixLen) (divs []*AddressDivision, newPref PrefixLen, isMultiple bool) {
	divs = make([]*AddressDivision, segCount)

	prefixedSegment := -1
	if assignedPrefLen != nil {
		p := assignedPrefLen.bitCount()
		if p < 0 {
			p = 0
			assignedPrefLen = cacheBitCount(p)
		} else {
			boundaryBits := BitCount(segCount << bitsToSegmentShift)
			if p > boundaryBits {
				p = boundaryBits
				assignedPrefLen = cacheBitCount(p)
			}
		}
		prefixedSegment = getNetworkSegmentIndex(p, bytesPerSegment, bitsPerSegment)
	}

	var previousSegPrefixed bool
	var lastSegment *IPAddressSegment
	for i := 0; i < segCount; i++ {
		segment := segProvider(i)
		if segment == nil {
			if previousSegPrefixed {
				divs[i] = zeroSegZeroPrefix.ToDiv()
			} else if i == prefixedSegment {
				newPref = cachePrefixLen(assignedPrefLen)
				segPref := getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), prefixedSegment)
				if i+1 < segCount && isPrefixSubnet(
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetSegmentValue()
					},
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetUpperSegmentValue()
					},
					segCount-(i+1), bytesPerSegment, bitsPerSegment, maxValuePerSegment, 0, zerosOnly) {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
					i++
					isMultiple = isMultiple || i < len(divs) || segPref.bitCount() < bitsPerSegment
					for ; i < len(divs); i++ {
						divs[i] = zeroSegPrefixBlock.ToDiv()
					}
					break
				} else {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
				}
			} else {
				divs[i] = zeroSeg.ToDiv() // nil segs are just zero
			}
		} else {
			// The final prefix length is the minimum amongst the assigned one and all of the segments' own prefixes
			segPrefix := segment.getDivisionPrefixLength()
			segIsPrefixed := segPrefix != nil
			if previousSegPrefixed {
				if !segIsPrefixed || segPrefix.bitCount() != 0 {
					divs[i] = createAddressDivision(
						segment.derivePrefixed(cacheBitCount(0))) // change seg prefix to 0
				} else {
					divs[i] = segment.ToDiv() // seg prefix is already 0
				}
			} else {
				// if a prefix length was supplied, we must check for prefix subnets
				var segPrefixSwitch bool
				var assignedSegPref PrefixLen
				if i == prefixedSegment || (prefixedSegment > 0 && segIsPrefixed) {
					// there exists an assigned prefix length
					assignedSegPref = getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), i)
					if segIsPrefixed {
						if assignedSegPref == nil || segPrefix.bitCount() < assignedSegPref.bitCount() {
							if segPrefix.bitCount() == 0 && i > 0 {
								// normalize boundaries by looking back
								if !lastSegment.IsPrefixed() {
									divs[i-1] = createAddressDivision(
										lastSegment.derivePrefixed(cacheBitCount(bitsPerSegment)))
								}
							}
							newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
						} else {
							newPref = cachePrefixLen(assignedPrefLen)
							segPrefixSwitch = assignedSegPref.bitCount() < segPrefix.bitCount()
						}
					} else {
						newPref = cachePrefixLen(assignedPrefLen)
						segPrefixSwitch = true
					}
					if isPrefixSubnet(
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetSegmentValue()
						},
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetUpperSegmentValue()
						},
						segCount,
						bytesPerSegment,
						bitsPerSegment,
						maxValuePerSegment,
						newPref.bitCount(),
						zerosOnly) {

						divs[i] = segment.toPrefixedNetworkDivision(assignedSegPref)
						i++
						isMultiple = isMultiple || i < len(divs) || newPref.bitCount() < bitsPerSegment
						for ; i < len(divs); i++ {
							divs[i] = zeroSegPrefixBlock.ToDiv()
						}
						break
					}
					previousSegPrefixed = true
				} else if segIsPrefixed {
					if segPrefix.bitCount() == 0 && i > 0 {
						// normalize boundaries by looking back
						if !lastSegment.IsPrefixed() {
							divs[i-1] = createAddressDivision(lastSegment.derivePrefixed(cacheBitCount(bitsPerSegment)))
						}
					}
					newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
					previousSegPrefixed = true
				}
				if segPrefixSwitch {
					divs[i] = createAddressDivision(segment.derivePrefixed(assignedSegPref)) // change seg prefix
				} else {
					divs[i] = segment.ToDiv()
				}
			}
			isMultiple = isMultiple || segment.isMultiple()
		}
		lastSegment = segment
	}
	return
}

// callers to this function supply segments with prefix length consistent with the supplied prefix length
func createSectionMultiple(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, isMultiple bool) *AddressSection {
	result := createSection(segments, prefixLength, addrType)
	result.isMult = isMultiple
	return result
}

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	assignedPrefixLength PrefixLen) (segments []*AddressDivision, err address_error.AddressValueError) {

	segments = createSegmentArray(segmentCount)
	byteIndex, segmentIndex := len(bytes), segmentCount-1
	for ; segmentIndex >= 0; segmentIndex-- {
		var value SegInt
		k := byteIndex - bytesPerSegment
		if k < 0 {
			k = 0
		}
		for j := k; j < byteIndex; j++ {
			byteValue := bytes[j]
			value <<= 8
			value |= SegInt(byteValue)
		}
		byteIndex = k
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, assignedPrefixLength, segmentIndex)
		seg := creator.createSegment(value, value, segmentPrefixLength)
		segments[segmentIndex] = seg
	}
	// any remaining bytes should be zero
	for byteIndex--; byteIndex >= 0; byteIndex-- {
		if bytes[byteIndex] != 0 {
			err = &addressValueError{
				addressError: addressError{key: "ipaddress.error.exceeds.size"},
				val:          int(bytes[byteIndex]),
			}
			break
		}
	}
	return
}

// callers to this function supply segments with prefix length consistent with the supplied prefix length
func deriveAddressSectionPrefLen(from *AddressSection, segments []*AddressDivision, prefixLength PrefixLen) *AddressSection {
	result := createSection(segments, prefixLength, from.getAddrType())
	result.initMultiple() // assigns isMultiple
	return result
}

// callers to this function supply segments with prefix length consistent with the prefix length of this section
func deriveAddressSection(from *AddressSection, segments []*AddressDivision) (res *AddressSection) {
	return deriveAddressSectionPrefLen(from, segments, from.prefixLength)
}
