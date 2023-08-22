package goip

import "unsafe"

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

func (grouping *addressDivisionGroupingInternal) matchesIPv4SectionType() bool {
	// because there are no init() conversions for IPV4 sections,
	// an implicitly zero-valued IPV4 section has addr type nil
	return grouping.getAddrType().isIPv4() || grouping.matchesZeroGrouping()
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

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}
