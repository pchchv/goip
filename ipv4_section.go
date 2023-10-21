package goip

import (
	"math/big"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

const (
	InetAtonRadixHex     InetAtonRadix = 16
	InetAtonRadixOctal   InetAtonRadix = 8
	InetAtonRadixDecimal InetAtonRadix = 10
)

var (
	ipv4CanonicalParams          = new(address_string.IPv4StringOptionsBuilder).ToOptions()
	ipv4NormalizedWildcardParams = new(address_string.IPv4StringOptionsBuilder).SetWildcardOptions(allWildcards).ToOptions()
	ipv4SqlWildcardParams        = new(address_string.IPv4StringOptionsBuilder).SetWildcardOptions(allSQLWildcards).ToOptions()
	ipv4FullParams               = new(address_string.IPv4StringOptionsBuilder).SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv4SegmentedBinaryParams    = new(address_string.IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv4SegmentSeparator).SetSegmentStrPrefix(BinaryPrefix).ToOptions()
	ipv4ReverseDNSParams         = new(address_string.IPv4StringOptionsBuilder).SetWildcardOptions(allWildcards).SetReverse(true).SetAddressSuffix(IPv4ReverseDnsSuffix).ToOptions()
	inetAtonHexParams            = new(address_string.IPv4StringOptionsBuilder).SetRadix(InetAtonRadixHex.GetRadix()).SetSegmentStrPrefix(InetAtonRadixHex.GetSegmentStrPrefix()).ToOptions()
	inetAtonOctalParams          = new(address_string.IPv4StringOptionsBuilder).SetRadix(InetAtonRadixOctal.GetRadix()).SetSegmentStrPrefix(InetAtonRadixOctal.GetSegmentStrPrefix()).ToOptions()
)

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

// Uint32Value returns the lowest address in the address section range as a uint32.
func (section *IPv4AddressSection) uint32Value() uint32 {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return 0
	}

	arr := section.getDivArray()
	val := uint32(arr[0].getDivisionValue())
	bitsPerSegment := section.GetBitsPerSegment()

	for i := 1; i < segCount; i++ {
		val = (val << uint(bitsPerSegment)) | uint32(arr[i].getDivisionValue())
	}

	return val
}

// UpperUint32Value returns the highest address in the address section range as a uint32.
func (section *IPv4AddressSection) UpperUint32Value() uint32 {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return 0
	}

	arr := section.getDivArray()
	val := uint32(arr[0].getUpperDivisionValue())
	bitsPerSegment := section.GetBitsPerSegment()

	for i := 1; i < segCount; i++ {
		val = (val << uint(bitsPerSegment)) | uint32(arr[i].getUpperDivisionValue())
	}

	return val
}

// ToPrefixBlock returns the section with the same prefix as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
//
// If this section has no prefix, this section is returned.
func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	return section.toPrefixBlock().ToIPv4()
}

// ToPrefixBlockLen returns the section with the same prefix of the given length as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
func (section *IPv4AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv4AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv4()
}

// ToBlock creates a new block of address sections by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (section *IPv4AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPv4AddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPv4()
}

// Uint32Value returns the lowest address in the address section range as a uint32.
func (section *IPv4AddressSection) Uint32Value() uint32 {
	cache := section.cache
	if cache == nil {
		return section.uint32Value()
	}

	res := (*uint32)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.uint32Cache))))
	if res == nil {
		val := section.uint32Value()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.uint32Cache))
		atomicStorePointer(dataLoc, unsafe.Pointer(&val))
		return val
	}

	return *res
}

// GetBitsPerSegment returns the number of bits comprising each segment in this section.  Segments in the same address section are equal length.
func (section *IPv4AddressSection) GetBitsPerSegment() BitCount {
	return IPv4BitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.  Segments in the same address section are equal length.
func (section *IPv4AddressSection) GetBytesPerSegment() int {
	return IPv4BytesPerSegment
}

// GetIPVersion returns IPv4, the IP version of this address section.
func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}

// IsMultiple returns  whether this section represents multiple values.
func (section *IPv4AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *IPv4AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

// GetIPv4Count returns the count of possible distinct values for this section.
// It is the same as GetCount but returns the value as a uint64 instead of a big integer.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions,
// or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (section *IPv4AddressSection) GetIPv4Count() uint64 {
	if section == nil {
		return 0
	}
	return section.getCachedCount().Uint64()
}

func (section *IPv4AddressSection) getIPv4Count() uint64 {
	if !section.isMultiple() {
		return 1
	}
	return longCount(section.ToSectionBase(), section.GetSegmentCount())
}

// GetCount returns the count of possible distinct values for this section.
// It is the same as GetIPv4Count but returns the value as a big integer instead of a uint64.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions,
// or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (section *IPv4AddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cacheCount(func() *big.Int {
		return bigZero().SetUint64(section.getIPv4Count())
	})
}

func (section *IPv4AddressSection) getCachedCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cachedCount(func() *big.Int {
		return bigZero().SetUint64(section.getIPv4Count())
	})
}

// GetIPv4PrefixCountLen returns the number of distinct prefix values in
// this item for the given prefix length.
//
// It is the same as GetPrefixCountLen but returns a uint64, not a *big.Int.
func (section *IPv4AddressSection) GetIPv4PrefixCountLen(prefixLength BitCount) uint64 {
	if !section.isMultiple() {
		return 1
	} else if prefixLength >= section.GetBitCount() {
		return section.GetIPv4Count()
	} else if prefixLength < 0 {
		prefixLength = 0
	}
	return longPrefixCount(section.ToSectionBase(), prefixLength)
}

func (section *IPv4AddressSection) getIPv4PrefixCount() uint64 {
	prefixLength := section.getPrefixLen()
	if prefixLength == nil {
		return section.GetIPv4Count()
	}
	return section.GetIPv4PrefixCountLen(prefixLength.bitCount())
}

// GetPrefixCount returns the number of distinct prefix values in this item.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the number of distinct prefix values.
//
// If this has a nil prefix length, returns the same value as GetCount.
func (section *IPv4AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return bigZero().SetUint64(section.getIPv4PrefixCount())
	})
}

// GetIPv4PrefixCount returns the number of distinct prefix values in this section.
// It is similar to GetPrefixCount but returns a uint64.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the number of distinct prefix values.
//
// If this has a nil prefix length, returns the same value as GetIPv4Count.
func (section *IPv4AddressSection) GetIPv4PrefixCount() uint64 {
	return section.cacheUint64PrefixCount(func() uint64 {
		return section.getIPv4PrefixCount()
	})
}

// GetPrefixCountLen returns the number of distinct prefix values in this item for the given prefix length.
func (section *IPv4AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen > bc {
		prefixLen = bc
	}
	return section.calcCount(func() *big.Int { return new(big.Int).SetUint64(section.GetIPv4PrefixCountLen(prefixLen)) })
}

// GetIPv4BlockCount returns the count of distinct values in the given number of initial (more significant) segments.
// It is similar to GetBlockCount but returns a uint64 instead of a big integer.
func (section *IPv4AddressSection) GetIPv4BlockCount(segmentCount int) uint64 {
	if !section.isMultiple() {
		return 1
	}
	return longCount(section.ToSectionBase(), segmentCount)
}

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
// It is similar to GetIPv4BlockCount but returns a big integer instead of a uint64.
func (section *IPv4AddressSection) GetBlockCount(segmentCount int) *big.Int {
	if segmentCount <= 0 {
		return bigOne()
	}
	return section.calcCount(func() *big.Int { return new(big.Int).SetUint64(section.GetIPv4BlockCount(segmentCount)) })
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.getDivision(index).ToIPv4()
}

// ForEachSegment visits each segment in order from most-significant to least,
// the most significant with index 0, calling the given function for each,
// terminating early if the function returns true.
// Returns the number of visited segments.
func (section *IPv4AddressSection) ForEachSegment(consumer func(segmentIndex int, segment *IPv4AddressSegment) (stop bool)) int {
	divArray := section.getDivArray()
	if divArray != nil {
		for i, div := range divArray {
			if consumer(i, div.ToIPv4()) {
				return i + 1
			}
		}
	}
	return len(divArray)
}

// GetNetworkSection returns a subsection containing the segments with the network bits of the section.
// The returned section will have only as many segments as needed as determined by the existing CIDR network prefix length.
//
// If this series has no CIDR prefix length, the returned network section will
// be the entire series as a prefixed section with prefix length matching the address bit length.
func (section *IPv4AddressSection) GetNetworkSection() *IPv4AddressSection {
	return section.getNetworkSection().ToIPv4()
}

// GetNetworkSectionLen returns a subsection containing the segments with the network of the section,
// the prefix bits according to the given prefix length.
// The returned section will have only as many segments as needed to contain the network.
//
// The new section will be assigned the given prefix length,
// unless the existing prefix length is smaller, in which case the existing prefix length will be retained.
func (section *IPv4AddressSection) GetNetworkSectionLen(prefLen BitCount) *IPv4AddressSection {
	return section.getNetworkSectionLen(prefLen).ToIPv4()
}

// GetHostSection returns a subsection containing the segments with the host of the address section,
// the bits beyond the CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
//
// If this series has no prefix length, the returned host section will be the full section.
func (section *IPv4AddressSection) GetHostSection() *IPv4AddressSection {
	return section.getHostSection().ToIPv4()
}

// GetHostSectionLen returns a subsection containing the segments with the host of the address section,
// the bits beyond the given CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
// The returned section will have an assigned prefix length indicating the beginning of the host.
func (section *IPv4AddressSection) GetHostSectionLen(prefLen BitCount) *IPv4AddressSection {
	return section.getHostSectionLen(prefLen).ToIPv4()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (section *IPv4AddressSection) CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int) {
	start, end, targetStart := adjust1To1StartIndices(start, end, section.GetDivisionCount(), len(segs))
	segs = segs[targetStart:]
	return section.forEachSubDivision(start, end, func(index int, div *AddressDivision) {
		segs[index] = div.ToIPv4()
	}, len(segs))
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (section *IPv4AddressSection) CopySegments(segs []*IPv4AddressSegment) (count int) {
	return section.ForEachSegment(func(index int, seg *IPv4AddressSegment) (stop bool) {
		if stop = index >= len(segs); !stop {
			segs[index] = seg
		}
		return
	})
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this section.
func (section *IPv4AddressSection) GetSegments() (res []*IPv4AddressSegment) {
	res = make([]*IPv4AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

// Mask applies the given mask to all address sections represented by this secction, returning the result.
//
// If the sections do not have a comparable number of segments, an error is returned.
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (section *IPv4AddressSection) Mask(other *IPv4AddressSection) (res *IPv4AddressSection, err address_error.IncompatibleAddressError) {
	return section.maskPrefixed(other, true)
}

func (section *IPv4AddressSection) maskPrefixed(other *IPv4AddressSection, retainPrefix bool) (res *IPv4AddressSection, err address_error.IncompatibleAddressError) {
	sec, err := section.mask(other.ToIP(), retainPrefix)
	if err == nil {
		res = sec.ToIPv4()
	}
	return
}

// MatchesWithMask applies the mask to this address section and then compares the result with the given address section,
// returning true if they match, false otherwise.  To match, both the given section and mask must have the same number of segments as this section.
func (section *IPv4AddressSection) MatchesWithMask(other *IPv4AddressSection, mask *IPv4AddressSection) bool {
	return section.matchesWithMask(other.ToIP(), mask.ToIP())
}

// GetLower returns the section in the range with the lowest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.2.4.5" is returned.
func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.getLower().ToIPv4()
}

// GetUpper returns the section in the range with the highest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.3.4.6" is returned.
func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.getUpper().ToIPv4()
}

// WithoutPrefixLen provides the same address section but with no prefix length.
// The values remain unchanged.
func (section *IPv4AddressSection) WithoutPrefixLen() *IPv4AddressSection {
	if !section.IsPrefixed() {
		return section
	}
	return section.withoutPrefixLen().ToIPv4()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address section.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (section *IPv4AddressSection) SetPrefixLen(prefixLen BitCount) *IPv4AddressSection {
	return section.setPrefixLen(prefixLen).ToIPv4()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address section.
//
// If this address section has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (section *IPv4AddressSection) AdjustPrefixLen(prefixLen BitCount) *IPv4AddressSection {
	return section.adjustPrefixLen(prefixLen).ToIPv4()
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by the given increment while zeroing out the bits that have moved into or outside the prefix.
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
func (section *IPv4AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv4AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv4(), err
}

// ToDivGrouping converts to an AddressDivisionGrouping,
// a polymorphic type usable with all address sections and division groupings.
// Afterwards, you can convert back with ToIPv4.
//
// ToDivGrouping can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv4AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return section.ToSectionBase().ToDivGrouping()
}

func (section *IPv4AddressSection) checkSectionCounts(sections []*IPv4AddressSection) address_error.SizeMismatchError {
	segCount := section.GetSegmentCount()
	length := len(sections)
	for i := 0; i < length; i++ {
		section2 := sections[i]
		if section2 == nil {
			continue
		}
		if section2.GetSegmentCount() != segCount {
			return &sizeMismatchError{incompatibleAddressError{addressError{key: "ipaddress.error.sizeMismatch"}}}
		}
	}
	return nil
}

// IsAdaptiveZero returns true if the division grouping was originally created as
// an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// that is, it was not constructed using a constructor function.
// Such a grouping that has no divisions or segments is converted to an implicitly zero-valued grouping of any type or version,
// whether IPv6, IPv4, MAC, or other.
// In other words, if a section or grouping is zero-value,
// it is equivalent and convertible to the zero value of any other section or grouping of any type.
func (section *IPv4AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

// GetSegmentStrings returns a slice with the string for each segment being the string that is normalized with wildcards.
func (section *IPv4AddressSection) GetSegmentStrings() []string {
	if section == nil {
		return nil
	}
	return section.getSegmentStrings()
}

// Contains returns whether this is same type and version as
// the given address section and whether it contains all values in the given section.
//
// Sections must also have the same number of segments to be comparable,
// otherwise false is returned.
func (section *IPv4AddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.contains(other)
}

// Equal returns whether the given address section is equal to this address section.
// Two address sections are equal if they represent the same set of sections.
// They must match:
//   - type/version: IPv4
//   - segment counts
//   - segment value ranges
//
// Prefix lengths are ignored.
func (section *IPv4AddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.equal(other)
}

// InetAtonRadix represents a radix for printing an address string.
type InetAtonRadix int

// GetRadix converts the radix to an int.
func (rad InetAtonRadix) GetRadix() int {
	return int(rad)
}

// GetSegmentStrPrefix returns the string prefix used to identify the radix.
func (rad InetAtonRadix) GetSegmentStrPrefix() string {
	if rad == InetAtonRadixOctal {
		return OctalPrefix
	} else if rad == InetAtonRadixHex {
		return HexPrefix
	}
	return ""
}

// String returns the name of the radix.
func (rad InetAtonRadix) String() string {
	if rad == InetAtonRadixOctal {
		return "octal"
	} else if rad == InetAtonRadixHex {
		return "hexadecimal"
	}
	return "decimal"
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

func newIPv4SectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err address_error.AddressValueError) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	expectedByteCount := segmentCount
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		ipv4Network.getIPAddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv4Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv4BitsToSegmentBitshift))
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

// NewIPv4SectionFromSegmentedBytes constructs an IPv4 address section from the given byte slice.
// It allows you to specify the segment count for the supplied bytes.
// If the slice is too large for the given number of segments, an error is returned, although leading zeros are tolerated.
func NewIPv4SectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv4AddressSection, err address_error.AddressValueError) {
	return newIPv4SectionFromBytes(bytes, segmentCount, nil, false)
}

// NewIPv4SectionFromPrefixedUint32 constructs an IPv4 address or prefix block section of
// the given segment count from the given value and prefix length.
func NewIPv4SectionFromPrefixedUint32(value uint32, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	if segmentCount < 0 {
		segmentCount = IPv4SegmentCount
	}

	segments := createSegmentsUint64(
		segmentCount,
		0,
		uint64(value),
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		ipv4Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv4Section(segments)

	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), false, false, BitCount(segmentCount<<ipv4BitsToSegmentBitshift))
	} else {
		res.cache.uint32Cache = &value
	}

	return
}

// NewIPv4SectionFromUint32 constructs an IPv4 address section of the given segment count from the given value.
func NewIPv4SectionFromUint32(value uint32, segmentCount int) (res *IPv4AddressSection) {
	return NewIPv4SectionFromPrefixedUint32(value, segmentCount, nil)
}

// NewIPv4SectionFromBytes constructs an IPv4 address section from the given byte slice.
// The segment count is determined by the slice length, even if the segment count exceeds 4 segments.
func NewIPv4SectionFromBytes(bytes []byte) *IPv4AddressSection {
	res, _ := newIPv4SectionFromBytes(bytes, len(bytes), nil, false)
	return res
}

func newIPv4SectionFromPrefixedSingle(vals, upperVals IPv4SegmentValueProvider, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}

	segments, isMultiple := createSegments(
		WrapIPv4SegmentValueProvider(vals),
		WrapIPv4SegmentValueProvider(upperVals),
		segmentCount,
		IPv4BitsPerSegment,
		ipv4Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv4Section(segments)
	res.isMult = isMultiple

	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv4BitsToSegmentBitshift))
	}

	return
}

// NewIPv4SectionFromPrefixedBytes constructs an IPv4 address or prefix block section from the given byte slice and prefix length.
// It allows you to specify the segment count for the supplied bytes.
// If the slice is too large for the given number of segments, an error is returned, although leading zeros are tolerated.
func NewIPv4SectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err address_error.AddressValueError) {
	return newIPv4SectionFromBytes(bytes, segmentCount, prefixLength, false)
}

// NewIPv4SectionFromPrefixedRange constructs an IPv4 subnet section of the given segment count from the given values and prefix length.
func NewIPv4SectionFromPrefixedRange(vals, upperVals IPv4SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	return newIPv4SectionFromPrefixedSingle(vals, upperVals, segmentCount, prefixLength, false)
}

// NewIPv4SectionFromVals constructs an IPv4 address section of the given segment count from the given values.
func NewIPv4SectionFromVals(vals IPv4SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4SectionFromPrefixedRange(vals, nil, segmentCount, nil)
	return
}

// NewIPv4SectionFromPrefixedVals constructs an IPv4 address or prefix block section of the given segment count from the given values and prefix length.
func NewIPv4SectionFromPrefixedVals(vals IPv4SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	return NewIPv4SectionFromPrefixedRange(vals, nil, segmentCount, prefixLength)
}

// NewIPv4SectionFromRange constructs an IPv4 subnet section of the given segment count from the given values.
func NewIPv4SectionFromRange(vals, upperVals IPv4SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4SectionFromPrefixedRange(vals, upperVals, segmentCount, nil)
	return
}

func getIPv4MaxValueLong(segmentCount int) uint64 {
	return macMaxValues[segmentCount]
}
