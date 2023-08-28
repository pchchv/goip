package goip

import "unsafe"

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
