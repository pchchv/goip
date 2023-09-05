package goip

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero-segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

// ToIP converts to an IPAddressSection, a polymorphic type usable with all IP address sections.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv4AddressSection) ToIP() *IPAddressSection {
	return (*IPAddressSection)(section)
}

// ToSectionBase converts to an AddressSection, a polymorphic type usable with all address sections.
// Afterwards, you can convert back with ToIPv4.
//
// ToSectionBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv4AddressSection) ToSectionBase() *AddressSection {
	return section.ToIP().ToSectionBase()
}

func createIPv4Section(segments []*AddressDivision) *IPv4AddressSection {
	return &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray(segments),
						addrType:  ipv4Type,
						cache: &valueCache{
							stringCache: stringCache{
								ipStringCache:   &ipStringCache{},
								ipv4StringCache: &ipv4StringCache{},
							},
						},
					},
				},
			},
		},
	}
}

// this one is used by that parsing code when there are prefix lengths to be applied
func newPrefixedIPv4SectionParsed(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection) {
	res = createIPv4Section(segments)
	res.isMult = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(len(segments)<<ipv4BitsToSegmentBitshift))
	}
	return
}

func newIPv4SectionParsed(segments []*AddressDivision, isMultiple bool) (res *IPv4AddressSection) {
	res = createIPv4Section(segments)
	res.isMult = isMultiple
	return
}

func createIPv4SectionFromSegs(orig []*IPv4AddressSegment, prefLen PrefixLen) (result *IPv4AddressSection) {
	divs, newPref, isMultiple := createDivisionsFromSegs(
		func(index int) *IPAddressSegment {
			return orig[index].ToIP()
		},
		len(orig),
		ipv4BitsToSegmentBitshift,
		IPv4BitsPerSegment,
		IPv4BytesPerSegment,
		IPv4MaxValuePerSegment,
		zeroIPv4Seg.ToIP(),
		zeroIPv4SegZeroPrefix.ToIP(),
		zeroIPv4SegPrefixBlock.ToIP(),
		prefLen)
	result = createIPv4Section(divs)
	result.prefixLength = newPref
	result.isMult = isMultiple
	return result
}

// NewIPv4Section constructs an IPv4 address or subnet section from the given segments.
func NewIPv4Section(segments []*IPv4AddressSegment) *IPv4AddressSection {
	return createIPv4SectionFromSegs(segments, nil)
}

// NewIPv4PrefixedSection constructs an IPv4 address or subnet section from the given segments and prefix length.
func NewIPv4PrefixedSection(segments []*IPv4AddressSegment, prefixLen PrefixLen) *IPv4AddressSection {
	return createIPv4SectionFromSegs(segments, prefixLen)
}
