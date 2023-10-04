package goip

import "math/big"

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

// GetBitsPerSegment returns the number of bits comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *MACAddressSection) GetBitsPerSegment() BitCount {
	return MACBitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *MACAddressSection) GetBytesPerSegment() int {
	return MACBytesPerSegment
}

// GetCount returns the count of possible distinct values for this item.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions, or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (section *MACAddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 6, 0x7fffffffffffff)
	})
}

func (section *MACAddressSection) getCachedCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cachedCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 6, 0x7fffffffffffff)
	})
}

// GetPrefixCount returns the number of distinct prefix values in this item.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the number of distinct prefix values.
//
// If this has a nil prefix length, returns the same value as GetCount.
func (section *MACAddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(section.getPrefixLen().bitCount())
	})
}

// GetPrefixCountLen returns the number of distinct prefix values in this item for the given prefix length.
func (section *MACAddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen >= bc {
		return section.GetCount()
	}

	networkSegmentIndex := getNetworkSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	hostSegmentIndex := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			if (networkSegmentIndex == hostSegmentIndex) && index == networkSegmentIndex {
				segmentPrefixLength := getPrefixedSegmentPrefixLength(section.GetBitsPerSegment(), prefixLen, index)
				return getPrefixValueCount(section.GetSegment(index).ToSegmentBase(), segmentPrefixLength.bitCount())
			}
			return section.GetSegment(index).GetValueCount()
		}, networkSegmentIndex+1, 6, 0x7fffffffffffff)
	})
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
