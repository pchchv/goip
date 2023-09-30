package goip

import (
	"math/big"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

var (
	zeroEmbeddedIPv6AddressSection = &EmbeddedIPv6AddressSection{}
	zeroIPv4AddressSection         = &IPv4AddressSection{}
	zeroIPv6AddressSection         = &IPv6AddressSection{}
	ffMACSeg                       = NewMACSegment(0xff)
	feMACSeg                       = NewMACSegment(0xfe)
)

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

// GetIPVersion returns IPv6, the IP version of this address section.
func (section *IPv6AddressSection) GetIPVersion() IPVersion {
	return IPv6
}

// GetBitsPerSegment returns the number of bits comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *IPv6AddressSection) GetBitsPerSegment() BitCount {
	return IPv6BitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *IPv6AddressSection) GetBytesPerSegment() int {
	return IPv6BytesPerSegment
}

// GetCount returns the count of possible distinct values for this item.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions,
// or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (section *IPv6AddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 2, 0x7fffffffffff)
	})
}

func (section *IPv6AddressSection) getCachedCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cachedCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 2, 0x7fffffffffff)
	})
}

// IsMultiple returns  whether this section represents multiple values.
func (section *IPv6AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *IPv6AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

// GetBlockCount returns the count of distinct values in
// the given number of initial (more significant) segments.
func (section *IPv6AddressSection) GetBlockCount(segments int) *big.Int {
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, segments, 2, 0x7fffffffffff)
	})
}

// GetPrefixCount returns the number of distinct prefix values in this item.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the number of distinct prefix values.
//
// If this has a nil prefix length, returns the same value as GetCount.
func (section *IPv6AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(section.getPrefixLen().bitCount())
	})
}

// GetPrefixCountLen returns the number of distinct prefix values in this item for the given prefix length.
func (section *IPv6AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
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
				return section.GetSegment(index).GetPrefixValueCount()
			}
			return section.GetSegment(index).GetValueCount()
		},
			networkSegmentIndex+1,
			2,
			0x7fffffffffff)
	})
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (section *IPv6AddressSection) GetSegment(index int) *IPv6AddressSegment {
	return section.getDivision(index).ToIPv6()
}

// GetNetworkSection returns a subsection containing the segments with the network bits of the section.
// The returned section will have only as many segments as needed as determined by the existing CIDR network prefix length.
//
// If this series has no CIDR prefix length, the returned network section will
// be the entire series as a prefixed section with prefix length matching the address bit length.
func (section *IPv6AddressSection) GetNetworkSection() *IPv6AddressSection {
	return section.getNetworkSection().ToIPv6()
}

// GetNetworkSectionLen returns a subsection containing the segments with the network of the address section,
// the prefix bits according to the given prefix length.
// The returned section will have only as many segments as needed to contain the network.
//
// The new section will be assigned the given prefix length,
// unless the existing prefix length is smaller, in which case the existing prefix length will be retained.
func (section *IPv6AddressSection) GetNetworkSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getNetworkSectionLen(prefLen).ToIPv6()
}

// GetHostSection returns a subsection containing the segments with the host of the address section,
// the bits beyond the CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
//
// If this series has no prefix length, the returned host section will be the full section.
func (section *IPv6AddressSection) GetHostSection() *IPv6AddressSection {
	return section.getHostSection().ToIPv6()
}

// GetHostSectionLen returns a subsection containing the segments with the host of the address section,
// the bits beyond the given CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
// The returned section will have an assigned prefix length indicating the beginning of the host.
func (section *IPv6AddressSection) GetHostSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getHostSectionLen(prefLen).ToIPv6()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (section *IPv6AddressSection) CopySubSegments(start, end int, segs []*IPv6AddressSegment) (count int) {
	start, end, targetStart := adjust1To1StartIndices(start, end, section.GetDivisionCount(), len(segs))
	segs = segs[targetStart:]
	return section.forEachSubDivision(start, end, func(index int, div *AddressDivision) {
		segs[index] = div.ToIPv6()
	}, len(segs))
}

// Mask applies the given mask to all address sections represented by this secction, returning the result.
//
// If the sections do not have a comparable number of segments, an error is returned.
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (section *IPv6AddressSection) Mask(other *IPv6AddressSection) (res *IPv6AddressSection, err address_error.IncompatibleAddressError) {
	return section.maskPrefixed(other, true)
}

func (section *IPv6AddressSection) maskPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err address_error.IncompatibleAddressError) {
	sec, err := section.mask(other.ToIP(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

// MatchesWithMask applies the mask to this address section and then compares the result with the given address section,
// returning true if they match, false otherwise.
// To match, both the given section and mask must have the same number of segments as this section.
func (section *IPv6AddressSection) MatchesWithMask(other *IPv6AddressSection, mask *IPv6AddressSection) bool {
	return section.matchesWithMask(other.ToIP(), mask.ToIP())
}

// GetLower returns the section in the range with the lowest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1::1:2-3:4:5-6", the section "1::1:2:4:5" is returned.
func (section *IPv6AddressSection) GetLower() *IPv6AddressSection {
	return section.getLower().ToIPv6()
}

// uint64Values returns the lowest address in the address range as a pair of uint64 values.
func (section *IPv6AddressSection) uint64Values() (high, low uint64) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return
	}

	arr := section.getDivArray()
	bitsPerSegment := section.GetBitsPerSegment()

	if segCount <= 4 {
		low = uint64(arr[0].getDivisionValue())
		for i := 1; i < segCount; i++ {
			low = (low << uint(bitsPerSegment)) | uint64(arr[i].getDivisionValue())
		}
	} else {
		high = uint64(arr[0].getDivisionValue())
		highCount := segCount - 4
		i := 1
		for ; i < highCount; i++ {
			high = (high << uint(bitsPerSegment)) | uint64(arr[i].getDivisionValue())
		}
		low = uint64(arr[i].getDivisionValue())
		for i++; i < segCount; i++ {
			low = (low << uint(bitsPerSegment)) | uint64(arr[i].getDivisionValue())
		}
	}

	return
}

// UpperUint64Values returns the highest address in the address section range as pair of uint64 values.
func (section *IPv6AddressSection) UpperUint64Values() (high, low uint64) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return
	}

	arr := section.getDivArray()
	bitsPerSegment := section.GetBitsPerSegment()

	if segCount <= 4 {
		low = uint64(arr[0].getUpperDivisionValue())
		for i := 1; i < segCount; i++ {
			low = (low << uint(bitsPerSegment)) | uint64(arr[i].getUpperDivisionValue())
		}
	} else {
		high = uint64(arr[0].getUpperDivisionValue())
		highCount := segCount - 4
		i := 1
		for ; i < highCount; i++ {
			high = (high << uint(bitsPerSegment)) | uint64(arr[i].getUpperDivisionValue())
		}
		low = uint64(arr[i].getUpperDivisionValue())
		for i++; i < segCount; i++ {
			low = (low << uint(bitsPerSegment)) | uint64(arr[i].getUpperDivisionValue())
		}
	}

	return
}

// GetUpper returns the section in the range with the highest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1::1:2-3:4:5-6", the section "1::1:3:4:6" is returned.
func (section *IPv6AddressSection) GetUpper() *IPv6AddressSection {
	return section.getUpper().ToIPv6()
}

// Uint64Values returns the lowest address in the address section range as a pair of uint64s.
func (section *IPv6AddressSection) Uint64Values() (high, low uint64) {
	cache := section.cache
	if cache == nil {
		return section.uint64Values()
	}

	res := (*uint128Cache)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.uint128Cache))))
	if res == nil {
		val := uint128Cache{}
		val.high, val.low = section.uint64Values()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.uint128Cache))
		atomicStorePointer(dataLoc, unsafe.Pointer(&val))
		return val.high, val.low
	}

	return res.high, res.low
}

type embeddedIPv6AddressSection struct {
	IPv6AddressSection
}

// EmbeddedIPv6AddressSection represents the initial IPv6 section of an IPv6v4MixedAddressGrouping.
type EmbeddedIPv6AddressSection struct {
	embeddedIPv6AddressSection
	encompassingSection *IPv6AddressSection
}

// IsPrefixBlock returns whether this address segment series has a prefix length and includes the block associated with its prefix length.
// If the prefix length matches the bit count, this returns true.
//
// This is different from ContainsPrefixBlock in that this method returns
// false if the series has no prefix length, or a prefix length that differs from a prefix length for which ContainsPrefixBlock returns true.
func (section *EmbeddedIPv6AddressSection) IsPrefixBlock() bool {
	ipv6Sect := section.encompassingSection
	if ipv6Sect == nil {
		ipv6Sect = zeroIPv6AddressSection
	}
	return ipv6Sect.IsPrefixBlock()
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

// SegmentSequenceList represents a list of SegmentSequence instances.
type SegmentSequenceList struct {
	ranges []SegmentSequence
}

func (list SegmentSequenceList) size() int {
	return len(list.ranges)
}

func (list SegmentSequenceList) getRange(index int) SegmentSequence {
	return list.ranges[index]
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
