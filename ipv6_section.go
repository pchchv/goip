package goip

import "github.com/pchchv/goip/address_error"

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero-segments.
type IPv6AddressSection struct {
	ipAddressSectionInternal
}

// ToIP converts to an IPAddressSection, a polymorphic type usable with all IP address sections.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv6AddressSection) ToIP() *IPAddressSection {
	return (*IPAddressSection)(section)
}

// ToSectionBase converts to an AddressSection, a polymorphic type usable with all address sections.
// Afterwards, you can convert back with ToIPv6.
//
// ToSectionBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv6AddressSection) ToSectionBase() *AddressSection {
	return section.ToIP().ToSectionBase()
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0,
// calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (section *IPv6AddressSection) ForEachSegment(consumer func(segmentIndex int, segment *IPv6AddressSegment) (stop bool)) int {
	divArray := section.getDivArray()
	if divArray != nil {
		for i, div := range divArray {
			if consumer(i, div.ToIPv6()) {
				return i + 1
			}
		}
	}
	return len(divArray)
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (section *IPv6AddressSection) CopySegments(segs []*IPv6AddressSegment) (count int) {
	return section.ForEachSegment(func(index int, seg *IPv6AddressSegment) (stop bool) {
		if stop = index >= len(segs); !stop {
			segs[index] = seg
		}
		return
	})
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this section.
func (section *IPv6AddressSection) GetSegments() (res []*IPv6AddressSegment) {
	res = make([]*IPv6AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

// ToPrefixBlock returns the section with the same prefix as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
//
// If this section has no prefix, this section is returned.
func (section *IPv6AddressSection) ToPrefixBlock() *IPv6AddressSection {
	return section.toPrefixBlock().ToIPv6()
}

// ToPrefixBlockLen returns the section with the same prefix of the given length as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
func (section *IPv6AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv6AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv6()
}

// ToBlock creates a new block of address sections by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (section *IPv6AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPv6AddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPv6()
}

type embeddedIPv6AddressSection struct {
	IPv6AddressSection
}

// EmbeddedIPv6AddressSection represents the initial IPv6 section of an IPv6v4MixedAddressGrouping.
type EmbeddedIPv6AddressSection struct {
	embeddedIPv6AddressSection
	encompassingSection *IPv6AddressSection
}

// IPv6v4MixedAddressGrouping has divisions that are a mix of IPv6 and IPv4 sections.
// It has an initial IPv6 section followed by an IPv4 section.
type IPv6v4MixedAddressGrouping struct {
	addressDivisionGroupingInternal
}

// IsMultiple returns  whether this grouping represents multiple values.
func (grouping *IPv6v4MixedAddressGrouping) IsMultiple() bool {
	return grouping != nil && grouping.isMultiple()
}

// IsPrefixed returns whether this grouping has an associated prefix length.
func (grouping *IPv6v4MixedAddressGrouping) IsPrefixed() bool {
	return grouping != nil && grouping.isPrefixed()
}

// ToDivGrouping converts to AddressDivisionGrouping, a polymorphic type used with all address sections and divisional groupings.
// The reverse conversion can then be performed using ToMixedIPv6v4.
//
// ToDivGrouping can be called with a nil receiver, allowing this method to be used in a chain with methods that can return a nil pointer.
func (grouping *IPv6v4MixedAddressGrouping) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(grouping)
}

// SegmentSequence represents a sequence of consecutive segments with
// the given length starting from the given segment index.
type SegmentSequence struct {
	index  int
	length int
}

func createIPv6Section(segments []*AddressDivision) *IPv6AddressSection {
	return &IPv6AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray(segments),
						addrType:  ipv6Type,
						cache: &valueCache{
							stringCache: stringCache{
								ipv6StringCache: &ipv6StringCache{},
								ipStringCache:   &ipStringCache{},
							},
						},
					},
				},
			},
		},
	}
}

func newPrefixedIPv6SectionParsed(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.isMult = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(len(segments)<<ipv6BitsToSegmentBitshift))
	}
	return
}

func createIPv6SectionFromSegs(orig []*IPv6AddressSegment, prefLen PrefixLen) (result *IPv6AddressSection) {
	divs, newPref, isMultiple := createDivisionsFromSegs(
		func(index int) *IPAddressSegment {
			return orig[index].ToIP()
		},
		len(orig),
		ipv6BitsToSegmentBitshift,
		IPv6BitsPerSegment,
		IPv6BytesPerSegment,
		IPv6MaxValuePerSegment,
		zeroIPv6Seg.ToIP(),
		zeroIPv6SegZeroPrefix.ToIP(),
		zeroIPv6SegPrefixBlock.ToIP(),
		prefLen)
	result = createIPv6Section(divs)
	result.prefixLength = newPref
	result.isMult = isMultiple
	return result
}

// NewIPv6Section constructs an IPv6 address or subnet section from the given segments.
func NewIPv6Section(segments []*IPv6AddressSegment) *IPv6AddressSection {
	return createIPv6SectionFromSegs(segments, nil)
}

func newIPv6SectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err address_error.AddressValueError) {
	if segmentCount < 0 {
		segmentCount = (len(bytes) + 1) >> 1
	}
	expectedByteCount := segmentCount << 1
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		ipv6Network.getIPAddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
		}
		if expectedByteCount == len(bytes) && len(bytes) > 0 {
			bytes = cloneBytes(bytes)
			res.cache.bytesCache = &bytesCache{lowerBytes: bytes}
			if !res.isMult { // not a prefix block
				res.cache.bytesCache.upperBytes = bytes
			}
		}
	}
	return
}

// NewIPv6SectionFromSegmentedBytes constructs an IPv6 address from the given byte slice.
// It allows you to specify the segment count for the supplied bytes.
// If the slice is too large for the given number of segments, an error is returned, although leading zeros are tolerated.
func NewIPv6SectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv6AddressSection, err address_error.AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, nil, false)
}

func newIPv6SectionParsed(segments []*AddressDivision, isMultiple bool) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.isMult = isMultiple
	return
}
