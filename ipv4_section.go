package goip

import (
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

const (
	InetAtonRadixHex     InetAtonRadix = 16
	InetAtonRadixOctal   InetAtonRadix = 8
	InetAtonRadixDecimal InetAtonRadix = 10
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
