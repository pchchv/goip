package goip

import (
	"math/big"

	"github.com/pchchv/goip/address_error"
)

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

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
func (section *MACAddressSection) GetBlockCount(segments int) *big.Int {
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		},
			segments, 6, 0x7fffffffffffff)
	})
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address section.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (section *MACAddressSection) SetPrefixLen(prefixLen BitCount) *MACAddressSection {
	return section.setPrefixLen(prefixLen).ToMAC()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address section.
//
// If this address section has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (section *MACAddressSection) AdjustPrefixLen(prefixLen BitCount) *AddressSection {
	return section.adjustPrefixLen(prefixLen).ToSectionBase()
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by
// the given increment while zeroing out the bits that have moved into or outside the prefix.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address section.
//
// If this address section has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
//
// When prefix length is increased, the bits moved within the prefix become zero.
// When a prefix length is decreased, the bits moved outside the prefix become zero.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (section *MACAddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToSectionBase(), err
}

// Wrap wraps this address section, returning a WrappedAddressSection,
// an implementation of ExtendedSegmentSeries,
// which can be used to write code that works with both addresses and address sections.
func (section *MACAddressSection) Wrap() WrappedAddressSection {
	return wrapSection(section.ToSectionBase())
}

// GetLower returns the section in the range with the lowest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1:1:1:2-3:4:5-6", the series "1:1:1:2:4:5" is returned.
func (section *MACAddressSection) GetLower() *MACAddressSection {
	return section.getLower().ToMAC()
}

// GetUpper returns the section in the range with the highest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1:1:1:2-3:4:5-6", the series "1:1:1:3:4:6" is returned.
func (section *MACAddressSection) GetUpper() *MACAddressSection {
	return section.getUpper().ToMAC()
}

// Uint64Value returns the lowest individual address section in
// the address section collection as a uint64.
func (section *MACAddressSection) Uint64Value() uint64 {
	return section.getLongValue(true)
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
