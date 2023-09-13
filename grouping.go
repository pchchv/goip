package goip

import (
	"math/big"
	"unsafe"
)

var emptyBytes = make([]byte, 0, 0)

type addressDivisionGroupingInternal struct {
	addressDivisionGroupingBase
}

// The adaptive zero grouping, produced by zero sections like IPv4AddressSection{} or AddressDivisionGrouping{},
// can represent a zero-length section of any address type,
// It is not considered equal to constructions of specific zero length sections of groupings like
// NewIPv4Section(nil) which can only represent a zero-length section of a single address type.
func (grouping *addressDivisionGroupingInternal) matchesZeroGrouping() bool {
	addrType := grouping.getAddrType()
	return addrType.isZeroSegments() && grouping.hasNoDivisions()
}

func (grouping *addressDivisionGroupingInternal) matchesIPSectionType() bool {
	// because there are no init() conversions for IPv6 or IPV4 sections, an implicitly zero-valued IPv4, IPv6 or IP section has addr type nil
	return grouping.getAddrType().isIP() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPAddressType() bool {
	return grouping.matchesIPSectionType() // no need to check segment count because addresses cannot be constructed with incorrect segment count (note the zero IPAddress has zero-segments)
}

func (grouping *addressDivisionGroupingInternal) matchesAddrSectionType() bool {
	addrType := grouping.getAddrType()
	// because there are no init() conversions for IPv6/IPV4/MAC sections,
	// an implicitly zero-valued IPv6/IPV4/MAC or zero IP section has addr type nil
	return addrType.isIP() || addrType.isMAC() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) isAddressSection() bool {
	return grouping != nil && grouping.matchesAddrSectionType()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6SectionType() bool {
	// because there are no init() conversions for IPv6 sections,
	// an implicitly zero-valued IPV6 section has addr type nil
	return grouping.getAddrType().isIPv6() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6v4MixedGroupingType() bool {
	// because there are no init() conversions for IPv6v4MixedGrouping groupings,
	// an implicitly zero-valued IPv6v4MixedGrouping has addr type nil
	return grouping.getAddrType().isIPv6v4Mixed() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4SectionType() bool {
	// because there are no init() conversions for IPV4 sections,
	// an implicitly zero-valued IPV4 section has addr type nil
	return grouping.getAddrType().isIPv4() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesMACSectionType() bool {
	// because there are no init() conversions for MAC sections,
	// an implicitly zero-valued MAC section has addr type nil
	return grouping.getAddrType().isMAC() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) getDivArray() standardDivArray {
	if divsArray := grouping.divisions; divsArray != nil {
		return divsArray.(standardDivArray)
	}
	return nil
}

// getDivision returns the division or panics if the index is negative or too large
func (grouping *addressDivisionGroupingInternal) getDivision(index int) *AddressDivision {
	return grouping.getDivArray()[index]
}

func (grouping *addressDivisionGroupingInternal) toAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(grouping))
}

func (grouping *addressDivisionGroupingInternal) getCachedCount() *big.Int {
	if !grouping.isMultiple() {
		return bigOne()
	} else {
		g := grouping.toAddressDivisionGrouping()
		if sect := g.ToIPv4(); sect != nil {
			return sect.getCachedCount()
		} else if sect := g.ToIPv6(); sect != nil {
			return sect.getCachedCount()
		} else if sect := g.ToMAC(); sect != nil {
			return sect.getCachedCount()
		}
	}
	return grouping.addressDivisionGroupingBase.getCachedCount()
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (grouping *addressDivisionGroupingInternal) GetBitCount() BitCount {
	return grouping.addressDivisionGroupingBase.GetBitCount()
}

// GetByteCount returns the number of bytes required for each value comprising this address item,
// rounding up if the bit count is not a multiple of 8.
func (grouping *addressDivisionGroupingInternal) GetByteCount() int {
	return grouping.addressDivisionGroupingBase.GetByteCount()
}

func (grouping *addressDivisionGroupingInternal) calcBytes() (bytes, upperBytes []byte) {
	addrType := grouping.getAddrType()
	divisionCount := grouping.GetDivisionCount()
	isMultiple := grouping.isMultiple()

	if addrType.isIPv4() || addrType.isMAC() {
		bytes = make([]byte, divisionCount)
		if isMultiple {
			upperBytes = make([]byte, divisionCount)
		} else {
			upperBytes = bytes
		}
		for i := 0; i < divisionCount; i++ {
			seg := grouping.getDivision(i).ToSegmentBase()
			bytes[i] = byte(seg.GetSegmentValue())
			if isMultiple {
				upperBytes[i] = byte(seg.GetUpperSegmentValue())
			}
		}
	} else if addrType.isIPv6() {
		byteCount := divisionCount << 1
		bytes = make([]byte, byteCount)
		if isMultiple {
			upperBytes = make([]byte, byteCount)
		} else {
			upperBytes = bytes
		}
		for i := 0; i < divisionCount; i++ {
			seg := grouping.getDivision(i).ToSegmentBase()
			byteIndex := i << 1
			val := seg.GetSegmentValue()
			bytes[byteIndex] = byte(val >> 8)
			var upperVal SegInt
			if isMultiple {
				upperVal = seg.GetUpperSegmentValue()
				upperBytes[byteIndex] = byte(upperVal >> 8)
			}
			nextByteIndex := byteIndex + 1
			bytes[nextByteIndex] = byte(val)
			if isMultiple {
				upperBytes[nextByteIndex] = byte(upperVal)
			}
		}
	} else {
		byteCount := grouping.GetByteCount()
		bytes = make([]byte, byteCount)
		if isMultiple {
			upperBytes = make([]byte, byteCount)
		} else {
			upperBytes = bytes
		}
		for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
			div := grouping.getDivision(k)
			val := div.GetDivisionValue()
			var upperVal DivInt
			if isMultiple {
				upperVal = div.GetUpperDivisionValue()
			}
			divBits := div.GetBitCount()
			for divBits > 0 {
				rbi := 8 - bitIndex
				bytes[byteIndex] |= byte(val << uint(rbi))
				val >>= uint(bitIndex)
				if isMultiple {
					upperBytes[byteIndex] |= byte(upperVal << uint(rbi))
					upperVal >>= uint(bitIndex)
				}
				if divBits < bitIndex {
					bitIndex -= divBits
					break
				} else {
					divBits -= bitIndex
					bitIndex = 8
					byteIndex--
				}
			}
		}
	}
	return
}

func (grouping *addressDivisionGroupingInternal) getBytes() (bytes []byte) {
	bytes, _ = grouping.getCachedBytes(grouping.calcBytes)
	return
}

func (grouping *addressDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getCachedBytes(grouping.calcBytes)
	return
}

// Bytes returns the lowest individual division grouping in this grouping as a byte slice.
func (grouping *addressDivisionGroupingInternal) Bytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	return cloneBytes(grouping.getBytes())
}

// UpperBytes returns the highest individual division grouping in this grouping as a byte slice.
func (grouping *addressDivisionGroupingInternal) UpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	return cloneBytes(grouping.getUpperBytes())
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6AddressType() bool {
	return grouping.getAddrType().isIPv6() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4AddressType() bool {
	return grouping.getAddrType().isIPv4() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesMACAddressType() bool {
	return grouping.getAddrType().isMAC()
}

// copySubDivisions copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (grouping *addressDivisionGroupingInternal) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	if divArray := grouping.getDivArray(); divArray != nil {
		start, end, targetIndex := adjust1To1Indices(start, end, grouping.GetDivisionCount(), len(divs))
		return divArray.copySubDivisions(start, end, divs[targetIndex:])
	}
	return
}

func (grouping *addressDivisionGroupingInternal) getDivisionCount() int {
	if divArray := grouping.getDivArray(); divArray != nil {
		return divArray.getDivisionCount()
	}
	return 0
}

func (grouping *addressDivisionGroupingInternal) initMultiple() {
	divCount := grouping.getDivisionCount()
	for i := divCount - 1; i >= 0; i-- {
		div := grouping.getDivision(i)
		if div.isMultiple() {
			grouping.isMult = true
			return
		}
	}
	return
}

// AddressDivisionGrouping objects consist of a series of AddressDivision objects,
// each containing a consistent range of values.
//
// AddressDivisionGrouping objects are immutable.
// This also makes them concurrency-safe.
//
// AddressDivision objects use uint64 to represent their values,
// so this places a limit on the size of the divisions in AddressDivisionGrouping.
//
// AddressDivisionGrouping objects are similar to address sections and addresses,
// except that groupings can have divisions of different bit-lengths,
// including divisions that are not the exact number of bytes,
// whereas all segments in an address or address section must have the same bit size and exact number of bytes.
type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

// ToSectionBase converts to an address section if the given grouping originated as an address section.
// Otherwise, the result is nil.
//
// ToSectionBase can be called with a nil receiver,
// allowing this method to be used in a chain with methods that may return a nil pointer.
func (grouping *AddressDivisionGrouping) ToSectionBase() *AddressSection {
	if grouping == nil || !grouping.isAddressSection() {
		return nil
	}
	return (*AddressSection)(unsafe.Pointer(grouping))
}

// ToIP converts to an IPAddressSection if this grouping originated as an IPv4 or IPv6 section,
// or an implicitly zero-valued IP section.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (grouping *AddressDivisionGrouping) ToIP() *IPAddressSection {
	return grouping.ToSectionBase().ToIP()
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

// ToIPv4 converts to an IPv4AddressSection if this grouping originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (grouping *AddressDivisionGrouping) ToIPv4() *IPv4AddressSection {
	return grouping.ToSectionBase().ToIPv4()
}

// ToIPv6 converts to an IPv6AddressSection if this grouping originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (grouping *AddressDivisionGrouping) ToIPv6() *IPv6AddressSection {
	return grouping.ToSectionBase().ToIPv6()
}

// ToMAC converts to a MACAddressSection if this grouping originated as a MAC section.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (grouping *AddressDivisionGrouping) ToMAC() *MACAddressSection {
	return grouping.ToSectionBase().ToMAC()
}

// ToDivGrouping is an identity method.
//
// ToDivGrouping can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (grouping *AddressDivisionGrouping) ToDivGrouping() *AddressDivisionGrouping {
	return grouping
}

// IsAdaptiveZero returns true if this is an adaptive zero grouping.
// The adaptive zero grouping, produced by zero sections like IPv4AddressSection{} or AddressDivisionGrouping{},
// can represent a zero-length section of any address type.
// It is not considered equal to constructions of specific zero length sections or
// groupings like NewIPv4Section(nil) which can only represent a zero-length section of a single address type.
func (grouping *AddressDivisionGrouping) IsAdaptiveZero() bool {
	return grouping != nil && grouping.matchesZeroGrouping()
}

// IsSectionBase returns true if this address division grouping originated as an address section.
// If so, use ToSectionBase to convert back to the section type.
func (grouping *AddressDivisionGrouping) IsSectionBase() bool {
	return grouping != nil && grouping.isAddressSection()
}

// IsIP returns true if this address division grouping originated as an IPv4 or IPv6 section, or a zero-length IP section.  If so, use ToIP to convert back to the IP-specific type.
func (grouping *AddressDivisionGrouping) IsIP() bool {
	return grouping.ToSectionBase().IsIP()
}

// IsMAC returns true if this grouping originated as a MAC section.  If so, use ToMAC to convert back to the MAC-specific type.
func (grouping *AddressDivisionGrouping) IsMAC() bool {
	return grouping.ToSectionBase().IsMAC()
}

// IsMixedIPv6v4 returns true if this grouping originated as a mixed IPv6-IPv4 grouping.  If so, use ToMixedIPv6v4 to convert back to the more specific grouping type.
func (grouping *AddressDivisionGrouping) IsMixedIPv6v4() bool {
	return grouping != nil && grouping.matchesIPv6v4MixedGroupingType()
}

// IsIPv4 returns true if this grouping originated as an IPv4 section.  If so, use ToIPv4 to convert back to the IPv4-specific type.
func (grouping *AddressDivisionGrouping) IsIPv4() bool {
	return grouping.ToSectionBase().IsIPv4()
}

// IsIPv6 returns true if this grouping originated as an IPv6 section.  If so, use ToIPv6 to convert back to the IPv6-specific type.
func (grouping *AddressDivisionGrouping) IsIPv6() bool {
	return grouping.ToSectionBase().IsIPv6()
}

func adjust1To1StartIndices(sourceStart, sourceEnd, sourceCount, targetCount int) (newSourceStart, newSourceEnd, newTargetStart int) {
	// both sourceCount and targetCount are lengths of their respective slices, so never negative
	targetStart := 0
	if sourceStart < 0 {
		targetStart -= sourceStart
		sourceStart = 0
		if targetStart > targetCount || targetStart < 0 {
			targetStart = targetCount
		}
	} else if sourceStart > sourceCount {
		sourceStart = sourceCount
	}

	if sourceEnd > sourceCount { // end index exceeds available
		sourceEnd = sourceCount
	} else if sourceEnd < sourceStart {
		sourceEnd = sourceStart
	}
	return sourceStart, sourceEnd, targetStart
}

func adjust1To1Indices(sourceStart, sourceEnd, sourceCount, targetCount int) (newSourceStart, newSourceEnd, newTargetStart int) {
	var targetStart int
	sourceStart, sourceEnd, targetStart = adjust1To1StartIndices(sourceStart, sourceEnd, sourceCount, targetCount)
	if limitEnd := sourceStart + (targetCount - targetStart); sourceEnd > limitEnd {
		sourceEnd = limitEnd
	}
	return sourceStart, sourceEnd, targetStart
}
