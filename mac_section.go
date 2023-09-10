package goip

// MACAddressSection is a section of a MACAddress.
//
// It is a series of 0 to 8 individual MAC address segments.
type MACAddressSection struct {
	addressSectionInternal
}

// IsMultiple returns whether this section represents multiple values.
func (section *MACAddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *MACAddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

// ToSectionBase converts to an AddressSection,
// a polymorphic type usable with all address sections.
// Afterwards, you can convert back with ToMAC.
//
// ToSectionBase can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *MACAddressSection) ToSectionBase() *AddressSection {
	return (*AddressSection)(section)
}

// ToDivGrouping converts to an AddressDivisionGrouping,
// a polymorphic type usable with all address sections and division groupings.
// Afterwards, you can convert back with ToMAC.
//
// ToDivGrouping can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *MACAddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return section.ToSectionBase().ToDivGrouping()
}

// IsAdaptiveZero returns true if the division grouping was originally created as
// an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// meaning it was not constructed using a constructor function.
// Such a grouping, which has no divisions or segments,
// is convertible to an implicitly zero-valued grouping of any type or version, whether IPv6, IPv4, MAC, or other.
// In other words, when a section or grouping is the zero-value,
// then it is equivalent and convertible to the zero value of any other section or grouping type.
func (section *MACAddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

func (section *MACAddressSection) getLongValue(lower bool) (result uint64) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return
	}

	seg := section.GetSegment(0)
	if lower {
		result = uint64(seg.GetSegmentValue())
	} else {
		result = uint64(seg.GetUpperSegmentValue())
	}

	bitsPerSegment := section.GetBitsPerSegment()

	for i := 1; i < segCount; i++ {
		result = result << uint(bitsPerSegment)
		seg = section.GetSegment(i)
		if lower {
			result |= uint64(seg.GetSegmentValue())
		} else {
			result |= uint64(seg.GetUpperSegmentValue())
		}
	}

	return
}

// ToPrefixBlock returns the section with the same prefix as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
//
// If this section has no prefix, this section is returned.
func (section *MACAddressSection) ToPrefixBlock() *MACAddressSection {
	return section.toPrefixBlock().ToMAC()
}

// ToPrefixBlockLen returns the section with the same prefix of the given length as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
func (section *MACAddressSection) ToPrefixBlockLen(prefLen BitCount) *MACAddressSection {
	return section.toPrefixBlockLen(prefLen).ToMAC()
}

// ToBlock creates a new block of address sections by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (section *MACAddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *MACAddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToMAC()
}

func createMACSection(segments []*AddressDivision) *MACAddressSection {
	return &MACAddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions: standardDivArray(segments),
					addrType:  macType,
					cache: &valueCache{
						stringCache: stringCache{
							macStringCache: &macStringCache{},
						},
					},
				},
			},
		},
	}
}

func newMACSectionParsed(segments []*AddressDivision, isMultiple bool) (res *MACAddressSection) {
	res = createMACSection(segments)
	res.initImplicitPrefLen(MACBitsPerSegment)
	res.isMult = isMultiple
	return
}

func createMACSectionFromSegs(orig []*MACAddressSegment) *MACAddressSection {
	var newPref PrefixLen
	segCount := len(orig)
	newSegs := make([]*AddressDivision, segCount)
	isMultiple := false

	if segCount != 0 {
		isBlock := true
		for i := segCount - 1; i >= 0; i-- {
			segment := orig[i]
			if segment == nil {
				segment = zeroMACSeg
				if isBlock && i != segCount-1 {
					newPref = getNetworkPrefixLen(MACBitsPerSegment, MACBitsPerSegment, i)
					isBlock = false
				}
			} else {
				if isBlock {
					minPref := segment.GetMinPrefixLenForBlock()
					if minPref > 0 {
						if minPref != MACBitsPerSegment || i != segCount-1 {
							newPref = getNetworkPrefixLen(MACBitsPerSegment, minPref, i)
						}
						isBlock = false
					}
				}
				isMultiple = isMultiple || segment.isMultiple()
			}
			newSegs[i] = segment.ToDiv()
		}
		if isBlock {
			newPref = cacheBitCount(0)
		}
	}

	res := createMACSection(newSegs)
	res.isMult = isMultiple
	res.prefixLength = newPref
	return res
}

// NewMACSection constructs a MAC address or address collection section from the given segments.
func NewMACSection(segments []*MACAddressSegment) *MACAddressSection {
	return createMACSectionFromSegs(segments)
}
