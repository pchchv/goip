package goip

import (
	"math/big"
	"math/bits"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

var (
	zeroEmbeddedIPv6AddressSection = &EmbeddedIPv6AddressSection{}
	zeroIPv4AddressSection         = &IPv4AddressSection{}
	zeroIPv6AddressSection         = &IPv6AddressSection{}
	ffMACSeg                       = NewMACSegment(0xff)
	feMACSeg                       = NewMACSegment(0xfe)
	compressAll                    = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.ZerosOrHost).ToOptions()
	compressMixed                  = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.MixedPreferred).ToOptions()
	compressAllNoSingles           = new(address_string.CompressOptionsBuilder).SetCompressionChoiceOptions(address_string.ZerosOrHost).ToOptions()
	compressHostPreferred          = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.HostPreferred).ToOptions()
	compressZeros                  = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.ZerosCompression).ToOptions()
	compressZerosNoSingles         = new(address_string.CompressOptionsBuilder).SetCompressionChoiceOptions(address_string.ZerosCompression).ToOptions()
	uncWildcards                   = new(address_string.WildcardOptionsBuilder).SetWildcardOptions(address_string.WildcardsNetworkOnly).SetWildcards(
		new(address_string.WildcardsBuilder).SetRangeSeparator(IPv6UncRangeSeparatorStr).SetWildcard(SegmentWildcardStr).ToWildcards()).ToOptions()
	base85Wildcards     = new(address_string.WildcardsBuilder).SetRangeSeparator(AlternativeRangeSeparatorStr).ToWildcards()
	mixedParams         = new(address_string.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressMixed).ToOptions()
	ipv6FullParams      = new(address_string.IPv6StringOptionsBuilder).SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv6CanonicalParams = new(address_string.IPv6StringOptionsBuilder).SetCompressOptions(compressAllNoSingles).ToOptions()
	uncParams           = new(address_string.IPv6StringOptionsBuilder).SetSeparator(IPv6UncSegmentSeparator).SetZoneSeparator(IPv6UncZoneSeparatorStr).
				SetAddressSuffix(IPv6UncSuffix).SetWildcardOptions(uncWildcards).ToOptions()
	ipv6CompressedParams         = new(address_string.IPv6StringOptionsBuilder).SetCompressOptions(compressAll).ToOptions()
	ipv6normalizedParams         = new(address_string.IPv6StringOptionsBuilder).ToOptions()
	canonicalWildcardParams      = new(address_string.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).SetCompressOptions(compressZerosNoSingles).ToOptions()
	ipv6NormalizedWildcardParams = new(address_string.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).ToOptions()    //no compression
	ipv6SqlWildcardParams        = new(address_string.IPv6StringOptionsBuilder).SetWildcardOptions(allSQLWildcards).ToOptions() //no compression
	wildcardCompressedParams     = new(address_string.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).SetCompressOptions(compressZeros).ToOptions()
	networkPrefixLengthParams    = new(address_string.IPv6StringOptionsBuilder).SetCompressOptions(compressHostPreferred).ToOptions()
	ipv6ReverseDNSParams         = new(address_string.IPv6StringOptionsBuilder).SetReverse(true).SetAddressSuffix(IPv6ReverseDnsSuffix).
					SetSplitDigits(true).SetExpandedSegments(true).SetSeparator('.').ToOptions()
	base85Params = new(address_string.IPStringOptionsBuilder).SetRadix(85).SetExpandedSegments(true).
			SetWildcards(base85Wildcards).SetZoneSeparator(IPv6AlternativeZoneSeparatorStr).ToOptions()
	ipv6SegmentedBinaryParams = new(address_string.IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv6SegmentSeparator).SetSegmentStrPrefix(BinaryPrefix).
					SetExpandedSegments(true).ToOptions()
	ipv6MaxValues = []*big.Int{
		bigZero(),
		new(big.Int).SetUint64(IPv6MaxValuePerSegment),
		new(big.Int).SetUint64(0xffffffff),
		new(big.Int).SetUint64(0xffffffffffff),
		maxInt(4),
		maxInt(5),
		maxInt(6),
		maxInt(7),
		maxInt(8),
	}
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

// WithoutPrefixLen provides the same address section but with no prefix length.
// The values remain unchanged.
func (section *IPv6AddressSection) WithoutPrefixLen() *IPv6AddressSection {
	if !section.IsPrefixed() {
		return section
	}
	return section.withoutPrefixLen().ToIPv6()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address section.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (section *IPv6AddressSection) SetPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.setPrefixLen(prefixLen).ToIPv6()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address section.
//
// If this address section has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (section *IPv6AddressSection) AdjustPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.adjustPrefixLen(prefixLen).ToIPv6()
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
func (section *IPv6AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) getZeroSegments(includeRanges bool) SegmentSequenceList {
	var currentIndex, currentCount, rangeCount int
	var ranges [IPv6SegmentCount >> 1]SegmentSequence
	divisionCount := section.GetSegmentCount()
	includeRanges = includeRanges && section.IsPrefixBlock() && section.GetPrefixLen().bitCount() < section.GetBitCount()
	if includeRanges {
		bitsPerSegment := section.GetBitsPerSegment()
		networkIndex := getNetworkSegmentIndex(section.getPrefixLen().bitCount(), section.GetBytesPerSegment(), bitsPerSegment)
		i := 0
		for ; i <= networkIndex; i++ {
			division := section.GetSegment(i)
			isCompressible := division.IsZero() ||
				(includeRanges && division.IsPrefixed() && division.isSinglePrefixBlock(0, division.getUpperDivisionValue(), division.getDivisionPrefixLength().bitCount()))
			if isCompressible {
				currentCount++
				if currentCount == 1 {
					currentIndex = i
				}
			} else if currentCount > 0 {
				ranges[rangeCount] = SegmentSequence{index: currentIndex, length: currentCount}
				rangeCount++
				currentCount = 0
			}
		}
		if currentCount > 0 {
			// add all segments past the network segment index to the current sequence
			ranges[rangeCount] = SegmentSequence{index: currentIndex, length: currentCount + divisionCount - i}
			rangeCount++
		} else if i < divisionCount {
			// all segments past the network segment index are a new sequence
			ranges[rangeCount] = SegmentSequence{index: i, length: divisionCount - i}
			rangeCount++
		} // else the very last segment was a network segment, and a prefix block segment, but the lowest segment value is not zero, eg ::100/120
	} else {
		for i := 0; i < divisionCount; i++ {
			division := section.GetSegment(i)
			if division.IsZero() {
				currentCount++
				if currentCount == 1 {
					currentIndex = i
				}
			} else if currentCount > 0 {
				ranges[rangeCount] = SegmentSequence{index: currentIndex, length: currentCount}
				rangeCount++
				currentCount = 0
			}
		}
		if currentCount > 0 {
			ranges[rangeCount] = SegmentSequence{index: currentIndex, length: currentCount}
			rangeCount++
		} else if rangeCount == 0 {
			return SegmentSequenceList{}
		}
	}
	return SegmentSequenceList{ranges[:rangeCount]}
}

// GetZeroSegments returns the list of consecutive zero-segments.
// Each element in the list will be an segment index and a total segment count for which
// that count of consecutive segments starting from that index are all zero.
func (section *IPv6AddressSection) GetZeroSegments() SegmentSequenceList {
	return section.getZeroSegments(false)
}

// GetZeroRangeSegments returns the list of consecutive zero and zero prefix block segments.
// Each element in the list will be an segment index and a total segment count for which
// that count of consecutive segments starting from that index are all zero or
// a prefix block segment with lowest segment value zero.
func (section *IPv6AddressSection) GetZeroRangeSegments() SegmentSequenceList {
	if section.IsPrefixed() {
		return section.getZeroSegments(true)
	}
	return section.getZeroSegments(false)
}

// GetCompressIndexAndCount chooses a single segment to be compressed in an IPv6 string.
// If no segment could be chosen then count is 0.
// If options is nil, no segment will be chosen.
// If createMixed is true, will assume the address string will be mixed IPv6/v4.
func (section *IPv6AddressSection) getCompressIndexAndCount(options address_string.CompressOptions, createMixed bool) (maxIndex, maxCount int) {
	if options != nil {
		rangeSelection := options.GetCompressionChoiceOptions()
		var compressibleSegs SegmentSequenceList
		if rangeSelection.CompressHost() {
			compressibleSegs = section.GetZeroRangeSegments()
		} else {
			compressibleSegs = section.GetZeroSegments()
		}
		maxCount = 0
		segmentCount := section.GetSegmentCount()
		//compressMixed := createMixed && options.GetMixedCompressionOptions().compressMixed(section)
		compressMixed := createMixed && compressMixedSect(options.GetMixedCompressionOptions(), section)
		preferHost := rangeSelection == address_string.HostPreferred
		preferMixed := createMixed && (rangeSelection == address_string.MixedPreferred)
		for i := compressibleSegs.size() - 1; i >= 0; i-- {
			rng := compressibleSegs.getRange(i)
			index := rng.index
			count := rng.length
			if createMixed {
				// so here we shorten the range to exclude the mixed part if necessary
				mixedIndex := IPv6MixedOriginalSegmentCount
				if !compressMixed ||
					index > mixedIndex || index+count < segmentCount { //range does not include entire mixed part.  We never compress only part of a mixed part.
					// the compressible range must stop at the mixed part
					if val := mixedIndex - index; val < count {
						count = val
					}
				}
			}
			// select this range if is the longest
			if count > 0 && count >= maxCount && (options.CompressSingle() || count > 1) {
				maxIndex = index
				maxCount = count
			}
			if preferHost && section.IsPrefixed() &&
				(BitCount(index+count)*section.GetBitsPerSegment()) > section.getNetworkPrefixLen().bitCount() { // this range contains the host
				// since we are going backwards, this means we select as the maximum any zero-segment that includes the host
				break
			}
			if preferMixed && index+count >= segmentCount { //this range contains the mixed section
				// since we are going backwards, this means we select to compress the mixed segment
				break
			}
		}
	}
	return
}

func (section *IPv6AddressSection) checkSectionCounts(sections []*IPv6AddressSection) address_error.SizeMismatchError {
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

// IsAdaptiveZero returns true if the division grouping was originally created as an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// meaning it was not constructed using a constructor function.
// Such a grouping, which has no divisions or segments, is convertible to an implicitly zero-valued grouping of any type or version, whether IPv6, IPv4, MAC, or other.
// In other words, when a section or grouping is the zero-value, then it is equivalent and convertible to the zero value of any other section or grouping type.
func (section *IPv6AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

// GetSegmentStrings returns a slice with the string for each segment being the string that is normalized with wildcards.
func (section *IPv6AddressSection) GetSegmentStrings() []string {
	if section == nil {
		return nil
	}
	return section.getSegmentStrings()
}

// ToDivGrouping converts to an AddressDivisionGrouping, a polymorphic type usable with all address sections and division groupings.
// Afterwards, you can convert back with ToIPv6.
//
// ToDivGrouping can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPv6AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return section.ToSectionBase().ToDivGrouping()
}

func (section *IPv6AddressSection) createNonMixedSection() *EmbeddedIPv6AddressSection {
	var result *IPv6AddressSection
	nonMixedCount := IPv6MixedOriginalSegmentCount
	mixedCount := section.GetSegmentCount() - nonMixedCount
	if mixedCount <= 0 {
		result = section
	} else {
		nonMixed := make([]*AddressDivision, nonMixedCount)
		section.copySubDivisions(0, nonMixedCount, nonMixed)
		result = createIPv6Section(nonMixed)
		result.initMultAndPrefLen()
	}

	return &EmbeddedIPv6AddressSection{
		embeddedIPv6AddressSection: embeddedIPv6AddressSection{*result},
		encompassingSection:        section,
	}
}

// Contains returns whether this is same type and version as the given address section and whether it contains all values in the given section.
//
// Sections must also have the same number of segments to be comparable, otherwise false is returned.
func (section *IPv6AddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.contains(other)
}

// Equal returns whether the given address section is equal to this address section.
// Two address sections are equal if they represent the same set of sections.
// They must match:
//   - type/version: IPv6
//   - segment count
//   - segment value ranges
//
// Prefix lengths are ignored.
func (section *IPv6AddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.equal(other)
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (section *IPv6AddressSection) GetTrailingSection(index int) *IPv6AddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (section *IPv6AddressSection) GetSubSection(index, endIndex int) *IPv6AddressSection {
	return section.getSubSection(index, endIndex).ToIPv6()
}

// BitwiseOr does the bitwise disjunction with this address section, useful when subnetting.
// It is similar to Mask which does the bitwise conjunction.
//
// The operation is applied to all individual addresses and the result is returned.
//
// If this represents multiple address sections, and applying the operation to all sections creates a set of sections
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (section *IPv6AddressSection) BitwiseOr(other *IPv6AddressSection) (res *IPv6AddressSection, err address_error.IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, true)
}

func (section *IPv6AddressSection) bitwiseOrPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err address_error.IncompatibleAddressError) {
	sec, err := section.bitwiseOr(other.ToIP(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

// SetPrefixLenZeroed sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address section.
// The provided prefix length will be adjusted to these boundaries if necessary.
//
// If this address section has a prefix length, and the prefix length is increased when setting the new prefix length, the bits moved within the prefix become zero.
// If this address section has a prefix length, and the prefix length is decreased when setting the new prefix length, the bits moved outside the prefix become zero.
//
// In other words, bits that move from one side of the prefix length to the other (bits moved into the prefix or outside the prefix) are zeroed.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (section *IPv6AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

// AssignMinPrefixForBlock returns an equivalent address section, assigned the smallest prefix length possible,
// such that the prefix block for that prefix length is in this address section.
//
// In other words, this method assigns a prefix length to this address section matching the largest prefix block in this address section.
func (section *IPv6AddressSection) AssignMinPrefixForBlock() *IPv6AddressSection {
	return section.assignMinPrefixForBlock().ToIPv6()
}

// Iterator provides an iterator to iterate through the individual address sections of this address section.
//
// When iterating, the prefix length is preserved.  Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual address sections.
//
// Call IsMultiple to determine if this instance represents multiple address sections, or GetCount for the count.
func (section *IPv6AddressSection) Iterator() Iterator[*IPv6AddressSection] {
	if section == nil {
		return ipv6SectionIterator{nilSectIterator()}
	}
	return ipv6SectionIterator{section.sectionIterator(nil)}
}

// BlockIterator Iterates through the address sections that can be obtained by iterating through all the upper segments up to the given segment count.
// The segments following remain the same in all iterated sections.
func (section *IPv6AddressSection) BlockIterator(segmentCount int) Iterator[*IPv6AddressSection] {
	return ipv6SectionIterator{section.blockIterator(segmentCount)}
}

// SequentialBlockIterator iterates through the sequential address sections that make up this address section.
//
// Practically, this means finding the count of segments for which the segments that follow are not full range,
// and then using BlockIterator with that segment count.
//
// Use GetSequentialBlockCount to get the number of iterated elements.
func (section *IPv6AddressSection) SequentialBlockIterator() Iterator[*IPv6AddressSection] {
	return ipv6SectionIterator{section.sequentialBlockIterator()}
}

// ReverseSegments returns a new section with the segments reversed.
func (section *IPv6AddressSection) ReverseSegments() *IPv6AddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, address_error.IncompatibleAddressError) {
			return section.GetSegment(i).WithoutPrefixLen().ToSegmentBase(), nil
		},
	)
	return res.ToIPv6()
}

// ReplaceLen replaces the segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
// ending before replacementEndIndex from the replacement section.
func (section *IPv6AddressSection) ReplaceLen(startIndex, endIndex int, replacement *IPv6AddressSection, replacementStartIndex, replacementEndIndex int) *IPv6AddressSection {
	return section.replaceLen(startIndex, endIndex, replacement.ToIP(), replacementStartIndex, replacementEndIndex, ipv6BitsToSegmentBitshift).ToIPv6()
}

// Replace replaces the segments of this section starting at the given index with the given replacement segments.
func (section *IPv6AddressSection) Replace(index int, replacement *IPv6AddressSection) *IPv6AddressSection {
	return section.ReplaceLen(index, index+replacement.GetSegmentCount(), replacement, 0, replacement.GetSegmentCount())
}

// Append creates a new section by appending the given section to this section.
func (section *IPv6AddressSection) Append(other *IPv6AddressSection) *IPv6AddressSection {
	count := section.GetSegmentCount()
	return section.ReplaceLen(count, count, other, 0, other.GetSegmentCount())
}

// Insert creates a new section by inserting the given section into this section at the given index.
func (section *IPv6AddressSection) Insert(index int, other *IPv6AddressSection) *IPv6AddressSection {
	return section.insert(index, other.ToIP(), ipv6BitsToSegmentBitshift).ToIPv6()
}

func (section *IPv6AddressSection) createEmbeddedIPv4AddressSection() (sect *IPv4AddressSection, err address_error.IncompatibleAddressError) {
	nonMixedCount := IPv6MixedOriginalSegmentCount
	segCount := section.GetSegmentCount()
	mixedCount := segCount - nonMixedCount
	lastIndex := segCount - 1
	var mixed []*AddressDivision
	if mixedCount == 0 {
		mixed = []*AddressDivision{}
	} else if mixedCount == 1 {
		mixed = make([]*AddressDivision, section.GetBytesPerSegment())
		last := section.GetSegment(lastIndex)
		if err := last.splitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
	} else {
		bytesPerSeg := section.GetBytesPerSegment()
		mixed = make([]*AddressDivision, bytesPerSeg<<1)
		low := section.GetSegment(lastIndex)
		high := section.GetSegment(lastIndex - 1)
		if err := high.splitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
		if err := low.splitIntoIPv4Segments(mixed, bytesPerSeg); err != nil {
			return nil, err
		}
	}
	sect = createIPv4Section(mixed)
	sect.initMultAndPrefLen()
	return
}

func (section *IPv6AddressSection) getMixedAddressGrouping() (*IPv6v4MixedAddressGrouping, address_error.IncompatibleAddressError) {
	cache := section.cache
	var sect *IPv6v4MixedAddressGrouping
	var mCache *mixedCache
	if cache != nil {
		mCache = (*mixedCache)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.mixed))))
		if mCache != nil {
			sect = mCache.defaultMixedAddressSection
		}
	}

	if sect == nil {
		mixedSect, err := section.createEmbeddedIPv4AddressSection()
		if err != nil {
			return nil, err
		}
		sect = newIPv6v4MixedGrouping(
			section.createNonMixedSection(),
			mixedSect,
		)
		if cache != nil {
			mixed := &mixedCache{
				defaultMixedAddressSection: sect,
				embeddedIPv6Section:        sect.GetIPv6AddressSection(),
				embeddedIPv4Section:        sect.GetIPv4AddressSection(),
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.mixed))
			atomicStorePointer(dataLoc, unsafe.Pointer(mixed))
		}
	}
	return sect, nil
}

// Gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
// which will correspond to between 0 and 4 bytes in this address.  Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.
func (section *IPv6AddressSection) getEmbeddedIPv4AddressSection() (*IPv4AddressSection, address_error.IncompatibleAddressError) {
	cache := section.cache
	if cache == nil {
		return section.createEmbeddedIPv4AddressSection()
	}
	sect, err := section.getMixedAddressGrouping()
	if err != nil {
		return nil, err
	}
	return sect.GetIPv4AddressSection(), nil
}

// GetIPv4AddressSection produces an IPv4 address section from a sequence of bytes in this IPv6 address section.
func (section *IPv6AddressSection) GetIPv4AddressSection(startByteIndex, endByteIndex int) (*IPv4AddressSection, address_error.IncompatibleAddressError) {
	if startByteIndex == IPv6MixedOriginalSegmentCount<<1 && endByteIndex == (section.GetSegmentCount()<<1) {
		return section.getEmbeddedIPv4AddressSection()
	}

	segments := make([]*AddressDivision, endByteIndex-startByteIndex)
	i := startByteIndex
	j := 0
	bytesPerSegment := section.GetBytesPerSegment()
	if i%bytesPerSegment == 1 {
		ipv6Segment := section.GetSegment(i >> 1)
		i++
		if err := ipv6Segment.splitIntoIPv4Segments(segments, j-1); err != nil {
			return nil, err
		}
		j++
	}

	for ; i < endByteIndex; i, j = i+bytesPerSegment, j+bytesPerSegment {
		ipv6Segment := section.GetSegment(i >> 1)
		if err := ipv6Segment.splitIntoIPv4Segments(segments, j); err != nil {
			return nil, err
		}
	}

	res := createIPv4Section(segments)
	res.initMultAndPrefLen()
	return res, nil
}

// GetNetworkMask returns the network mask associated with the CIDR network prefix length of this address section.
// If this section has no prefix length, then the all-ones mask is returned.
func (section *IPv6AddressSection) GetNetworkMask() *IPv6AddressSection {
	return section.getNetworkMask(ipv6Network).ToIPv6()
}

// GetHostMask returns the host mask associated with the CIDR network prefix length of this address section.
// If this section has no prefix length, then the all-ones mask is returned.
func (section *IPv6AddressSection) GetHostMask() *IPv6AddressSection {
	return section.getHostMask(ipv6Network).ToIPv6()
}

// ToZeroHost converts the address section to one in which all individual address sections have a host of zero,
// the host being the bits following the prefix length.
// If the address section has no prefix length, then it returns an all-zero address section.
//
// The returned section will have the same prefix and prefix length.
//
// This returns an error if the section is a range of address sections which cannot be converted to
// a range in which all sections have zero hosts,
// because the conversion results in a segment that is not a sequential range of values.
func (section *IPv6AddressSection) ToZeroHost() (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.toZeroHost(false)
	return res.ToIPv6(), err
}

// ToZeroHostLen converts the address section to one in which all individual sections have a host of zero,
// the host being the bits following the given prefix length.
// If this address section has the same prefix length, then the returned one will too,
// otherwise the returned section will have no prefix length.
//
// This returns an error if the section is a range of which cannot be converted to
// a range in which all sections have zero hosts,
// because the conversion results in a segment that is not a sequential range of values.
func (section *IPv6AddressSection) ToZeroHostLen(prefixLength BitCount) (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.toZeroHostLen(prefixLength)
	return res.ToIPv6(), err
}

// ToZeroNetwork converts the address section to one in which all individual address sections have a network of zero,
// the network being the bits within the prefix length.
// If the address section has no prefix length, then it returns an all-zero address section.
//
// The returned address section will have the same prefix length.
func (section *IPv6AddressSection) ToZeroNetwork() *IPv6AddressSection {
	return section.toZeroNetwork().ToIPv6()
}

// ToMaxHost converts the address section to one in which all individual address sections have a host of all one-bits, the max value,
// the host being the bits following the prefix length.
// If the address section has no prefix length, then it returns an all-ones section, the max address section.
//
// The returned address section will have the same prefix and prefix length.
//
// This returns an error if the address section is a range of address sections which cannot be converted to
// a range in which all sections have max hosts,
// because the conversion results in a segment that is not a sequential range of values.
func (section *IPv6AddressSection) ToMaxHost() (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.toMaxHost()
	return res.ToIPv6(), err
}

// ReverseBits returns a new section with the bits reversed.  Any prefix length is dropped.
//
// If the bits within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, this returns an error.
//
// In practice this means that to be reversible,
// a range must include all values except possibly the largest and/or smallest,
// which reverse to themselves.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (section *IPv6AddressSection) ReverseBits(perByte bool) (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.reverseBits(perByte)
	return res.ToIPv6(), err
}

// ReverseBytes returns a new section with the bytes reversed.
// Any prefix length is dropped.
//
// If the bytes within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, then this returns an error.
//
// In practice this means that to be reversible,
// a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
func (section *IPv6AddressSection) ReverseBytes() (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.reverseBytes(false)
	return res.ToIPv6(), err
}

// ToMaxHostLen converts the address section to one in which all individual address sections have a host of all one-bits, the max host,
// the host being the bits following the given prefix length.
// If this section has the same prefix length,
// then the resulting section will too, otherwise the resulting section will have no prefix length.
//
// For instance, the zero host of "1.2.3.4" for the prefix length of 16 is the address "1.2.255.255".
//
// This returns an error if the section is a range of address sections which cannot be converted to
// a range in which all address sections have max hosts,
// because the conversion results in a segment that is not a sequential range of values.
func (section *IPv6AddressSection) ToMaxHostLen(prefixLength BitCount) (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.toMaxHostLen(prefixLength)
	return res.ToIPv6(), err
}

// ToBase85String creates a base 85 string,
// which is described in [RFC 1924](https://www.rfc-editor.org/rfc/rfc1924.html).
// It may be written as a range of two values if a range is not a prefix block.
//
// If a multi-valued section cannot be written as a single prefix block or a range of two values,
// an error is returned.
func (section *IPv6AddressSection) ToBase85String() (string, address_error.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}

	cache := section.getStringCache()
	if cache == nil {
		return section.toBase85String(NoZone)
	}

	cacheField := &cache.base85String
	return cacheStrErr(cacheField,
		func() (string, address_error.IncompatibleAddressError) {
			return section.toBase85String(NoZone)
		})
}

func (section *IPv6AddressSection) toBase85String(zone Zone) (string, address_error.IncompatibleAddressError) {
	if isDual, err := section.isDualString(); err != nil {
		return "", err
	} else {
		var largeGrouping *IPAddressLargeDivisionGrouping
		if section.hasNoDivisions() {
			largeGrouping = NewIPAddressLargeDivGrouping(nil)
		} else {
			bytes := section.getBytes()
			prefLen := section.getNetworkPrefixLen()
			bitCount := section.GetBitCount()
			var div *IPAddressLargeDivision
			if isDual {
				div = NewIPAddressLargeRangePrefixDivision(bytes, section.getUpperBytes(), prefLen, bitCount, 85)
			} else {
				div = NewIPAddressLargePrefixDivision(bytes, prefLen, bitCount, 85)
			}
			largeGrouping = NewIPAddressLargeDivGrouping([]*IPAddressLargeDivision{div})
		}
		return toNormalizedIPZonedString(base85Params, largeGrouping, zone), nil
	}
}

// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this address section.
// The returned block will have an assigned prefix length indicating the prefix length for the block.
//
// There may be no such address section - it is required that the range of values match the range of a prefix block.
// If there is no such address section, then nil is returned.
func (section *IPv6AddressSection) AssignPrefixForSingleBlock() *IPv6AddressSection {
	return section.assignPrefixForSingleBlock().ToIPv6()
}

// Increment returns the item that is the given increment upwards into the range,
// with the increment of 0 returning the first in the range.
//
// If the increment i matches or exceeds the range count c, then i - c + 1
// is added to the upper item of the range.
// An increment matching the count gives you the item just above the highest in the range.
//
// If the increment is negative, it is added to the lowest of the range.
// To get the item just below the lowest of the range, use the increment -1.
//
// If this represents just a single value, the item is simply incremented by the given increment, positive or negative.
//
// If this item represents multiple values, a positive increment i is equivalent i + 1 values from the iterator and beyond.
// For instance, a increment of 0 is the first value from the iterator, an increment of 1 is the second value from the iterator, and so on.
// An increment of a negative value added to the count is equivalent to the same number of iterator values preceding the last value of the iterator.
// For instance, an increment of count - 1 is the last value from the iterator, an increment of count - 2 is the second last value, and so on.
//
// On overflow or underflow, Increment returns nil.
func (section *IPv6AddressSection) Increment(increment int64) *IPv6AddressSection {
	if increment == 0 && !section.isMultiple() {
		return section
	}

	var bigIncrement big.Int
	count := section.GetCount()
	bigIncrement.SetInt64(increment)
	lowerValue := section.GetValue()
	upperValue := section.GetUpperValue()
	if checkOverflowBig(increment, &bigIncrement, lowerValue, upperValue, count, func() *big.Int { return getIPv6MaxValue(section.GetSegmentCount()) }) {
		return nil
	}

	prefixLength := section.getPrefixLen()
	result := fastIncrement(section.ToSectionBase(), increment, ipv6Network.getIPAddressCreator(), section.getLower, section.getUpper, prefixLength)
	if result != nil {
		return result.ToIPv6()
	}

	bigIncrement.SetInt64(increment)
	return incrementBig(section.ToSectionBase(), increment, &bigIncrement, ipv6Network.getIPAddressCreator(), section.getLower, section.getUpper, prefixLength).ToIPv6()
}

// Compare returns a negative integer, zero,
// or a positive integer if this address section is less than, equal,
// or greater than the given item.
// Any address item is comparable to any other.
// All address items use CountComparator to compare.
func (section *IPv6AddressSection) Compare(item AddressItem) int {
	return CountComparator.Compare(section, item)
}

// CompareSize compares the counts of two items,
// the number of individual sections represented.
//
// Rather than calculating counts with GetCount,
// there can be more efficient ways of determining whether one item represents more individual items than another.
//
// CompareSize returns a positive integer if this address section has a larger count than the item given,
// zero if they are the same, or a negative integer if the other has a larger count.
func (section *IPv6AddressSection) CompareSize(other AddressItem) int {
	if section == nil {
		if isNilItem(other) {
			return 0
		}
		// have size 0, other has size >= 1
		return -1
	}
	return section.compareSize(other)
}

// Subtract subtracts the given subnet sections from this subnet section,
// returning an array of sections for the result
// (the subnet sections will not be contiguous so an array is required).
//
// Subtract  computes the subnet difference,
// the set of address sections in this address section but not in the provided section.
// This is also known as the relative complement of the given argument in this subnet section.
//
// This is set subtraction, not subtraction of values.
func (section *IPv6AddressSection) Subtract(other *IPv6AddressSection) (res []*IPv6AddressSection, err address_error.SizeMismatchError) {
	sections, err := section.subtract(other.ToIP())
	if err == nil {
		res = cloneTo(sections, (*IPAddressSection).ToIPv6)
	}
	return
}

// Intersect returns the subnet sections whose individual sections are found in both this and the given subnet section argument,
// or nil if no such sections exist.
//
// This is also known as the conjunction of the two sets of address sections.
//
// If the two sections have different segment counts, an error is returned.
func (section *IPv6AddressSection) Intersect(other *IPv6AddressSection) (res *IPv6AddressSection, err address_error.SizeMismatchError) {
	sec, err := section.intersect(other.ToIP())
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

// PrefixIterator provides an iterator to iterate through the individual prefixes of this address section,
// each iterated element spanning the range of values for its prefix.
//
// It is similar to the prefix block iterator,
// except for possibly the first and last iterated elements,
// which might not be prefix blocks,
// instead constraining themselves to values from this address section.
//
// If the series has no prefix length, then this is equivalent to Iterator.
func (section *IPv6AddressSection) PrefixIterator() Iterator[*IPv6AddressSection] {
	return ipv6SectionIterator{section.prefixIterator(false)}
}

// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks,
// one for each prefix of this address section.
// Each iterated address section will be a prefix block with the same prefix length as this address section.
//
// If this address section has no prefix length, then this is equivalent to Iterator.
func (section *IPv6AddressSection) PrefixBlockIterator() Iterator[*IPv6AddressSection] {
	return ipv6SectionIterator{section.prefixIterator(true)}
}

// IncrementBoundary returns the item that is the given increment from the range boundaries of this item.
//
// If the given increment is positive,
// adds the value to the highest (GetUpper) in the range to produce a new item.
// If the given increment is negative,
// adds the value to the lowest (GetLower) in the range to produce a new item.
// If the increment is zero, returns this.
//
// If this represents just a single value,
// this item is simply incremented by the given increment value,
// positive or negative.
//
// On overflow or underflow, IncrementBoundary returns nil.
func (section *IPv6AddressSection) IncrementBoundary(increment int64) *IPv6AddressSection {
	return section.incrementBoundary(increment).ToIPv6()
}

// SpanWithPrefixBlocks returns an array of prefix blocks that spans the same set of individual address sections as this section.
//
// Unlike SpanWithPrefixBlocksTo,
// the result only includes blocks that are a part of this section.
func (section *IPv6AddressSection) SpanWithPrefixBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPv6AddressSection{section}
		}
		wrapped := wrapIPSection(section.ToIP())
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv6Sections(spanning)
	}
	wrapped := wrapIPSection(section.ToIP())
	return cloneToIPv6Sections(spanWithPrefixBlocks(wrapped))
}

// SpanWithPrefixBlocksTo returns the smallest slice of prefix block subnet sections that span from this section to the given section.
//
// If the given section has a different segment count, an error is returned.
//
// The resulting slice is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) SpanWithPrefixBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, address_error.SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIP()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningPrefixBlocks(
			wrapIPSection(section.ToIP()),
			wrapIPSection(other.ToIP()),
		),
	), nil
}

// SpanWithSequentialBlocks produces the smallest slice of sequential blocks that cover the same set of sections as this.
//
// This slice can be shorter than that produced by SpanWithPrefixBlocks and is never longer.
//
// Unlike SpanWithSequentialBlocksTo,
// this method only includes values that are a part of this section.
func (section *IPv6AddressSection) SpanWithSequentialBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		return []*IPv6AddressSection{section}
	}
	wrapped := wrapIPSection(section.ToIP())
	return cloneToIPv6Sections(spanWithSequentialBlocks(wrapped))
}

// SpanWithSequentialBlocksTo produces the smallest slice of sequential block address sections that span from this section to the given section.
func (section *IPv6AddressSection) SpanWithSequentialBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, address_error.SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIP()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningSequentialBlocks(
			wrapIPSection(section.ToIP()),
			wrapIPSection(other.ToIP()),
		),
	), nil
}

// CoverWithPrefixBlockTo returns the minimal-size prefix block section that covers all the address sections spanning from this to the given section.
//
// If the other section has a different segment count, an error is returned.
func (section *IPv6AddressSection) CoverWithPrefixBlockTo(other *IPv6AddressSection) (*IPv6AddressSection, address_error.SizeMismatchError) {
	res, err := section.coverWithPrefixBlockTo(other.ToIP())
	return res.ToIPv6(), err
}

// CoverWithPrefixBlock returns the minimal-size prefix block that covers all the individual address sections in this section.
// The resulting block will have a larger count than this,
// unless this section is already a prefix block.
func (section *IPv6AddressSection) CoverWithPrefixBlock() *IPv6AddressSection {
	return section.coverWithPrefixBlock().ToIPv6()
}

// MergeToSequentialBlocks merges this with the list of sections to produce the smallest array of sequential blocks.
//
// The resulting slice is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToSequentialBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, address_error.SizeMismatchError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}

	series := cloneIPv6Sections(section, sections)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

// MergeToPrefixBlocks merges this section with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting slice is sorted from lowest value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToPrefixBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, address_error.SizeMismatchError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}

	series := cloneIPv6Sections(section, sections)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

// String implements the [fmt.Stringer] interface,
// returning the normalized string provided by ToNormalizedString,
// or "<nil>" if the receiver is a nil pointer.
func (section *IPv6AddressSection) String() string {
	if section == nil {
		return nilString()
	}
	return section.toString()
}

// ToHexString writes this address section as a single hexadecimal value
// (possibly two values if a range that is not a prefixed block),
// the number of digits according to the bit count, with or without a preceding "0x" prefix.
//
// If a multiple-valued section cannot be written as a single prefix block or a range of two values, an error is returned.
func (section *IPv6AddressSection) ToHexString(with0xPrefix bool) (string, address_error.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toHexString(with0xPrefix)
}

// ToOctalString writes this address section as a single octal value (possibly two values if a range that is not a prefixed block),
// the number of digits according to the bit count, with or without a preceding "0" prefix.
//
// If a multiple-valued section cannot be written as a single prefix block or a range of two values, an error is returned.
func (section *IPv6AddressSection) ToOctalString(with0Prefix bool) (string, address_error.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toOctalString(with0Prefix)
}

// ToBinaryString writes this address section as a single binary value (possibly two values if a range that is not a prefixed block),
// the number of digits according to the bit count, with or without a preceding "0b" prefix.
//
// If a multiple-valued section cannot be written as a single prefix block or a range of two values, an error is returned.
func (section *IPv6AddressSection) ToBinaryString(with0bPrefix bool) (string, address_error.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toBinaryString(with0bPrefix)
}

func (section *IPv6AddressSection) toSegmentedBinaryStringZoned(zone Zone) string {
	return section.ipAddressSectionInternal.toCustomZonedString(ipv6SegmentedBinaryParams, zone)
}

func (section *IPv6AddressSection) toNormalizedMixedString(mixedParams *ipv6v4MixedParams, zone Zone) (string, address_error.IncompatibleAddressError) {
	mixed, err := section.getMixedAddressGrouping()
	if err != nil {
		return "", err
	}
	return mixedParams.toZonedString(mixed, zone), nil
}

func (section *IPv6AddressSection) toNormalizedMixedZonedString(options address_string.IPv6StringOptions, zone Zone) (string, address_error.IncompatibleAddressError) {
	stringParams := from(options, section)
	if stringParams.nextUncompressedIndex <= IPv6MixedOriginalSegmentCount { // the mixed section is not compressed
		mixedParams := &ipv6v4MixedParams{
			ipv6Params: stringParams,
			ipv4Params: toIPParams(options.GetIPv4Opts()),
		}
		return section.toNormalizedMixedString(mixedParams, zone)
	}
	// the mixed section is compressed
	return stringParams.toZonedString(section, zone), nil
}

func (section *IPv6AddressSection) toNormalizedZonedString(options address_string.IPv6StringOptions, zone Zone) string {
	return from(options, section).toZonedString(section, zone)
}

func (section *IPv6AddressSection) toNormalizedSplitZonedString(options address_string.IPv6StringOptions, zone Zone) (string, address_error.IncompatibleAddressError) {
	return from(options, section).toZonedSplitString(section, zone)
}

// ToCustomString creates a customized string from this address section according to the given string option parameters.
//
// Errors can result from split digits with ranged values, or mixed IPv4/v6 with ranged values, when the segment ranges are incompatible.
func (section *IPv6AddressSection) ToCustomString(stringOptions address_string.IPv6StringOptions) (string, address_error.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toCustomString(stringOptions, NoZone)
}

func (section *IPv6AddressSection) toCustomString(stringOptions address_string.IPv6StringOptions, zone Zone) (string, address_error.IncompatibleAddressError) {
	if stringOptions.IsMixed() {
		return section.toNormalizedMixedZonedString(stringOptions, zone)
	} else if stringOptions.IsSplitDigits() {
		return section.toNormalizedSplitZonedString(stringOptions, zone)
	}
	return section.toNormalizedZonedString(stringOptions, zone), nil
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

// IsAdaptiveZero returns true if the division grouping was originally created as
// an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// meaning it was not constructed using a constructor function.
// Such a grouping, which has no divisions or segments, is convertible to
// an implicitly zero-valued grouping of any type or version, whether IPv6, IPv4, MAC, or other.
// In other words, when a section or grouping is the zero-value, then it is equivalent and convertible to
// the zero value of any other section or grouping type.
func (grouping *IPv6v4MixedAddressGrouping) IsAdaptiveZero() bool {
	return grouping != nil && grouping.matchesZeroGrouping()
}

// GetIPv6AddressSection returns the initial IPv6 section of the grouping.
func (grouping *IPv6v4MixedAddressGrouping) GetIPv6AddressSection() *EmbeddedIPv6AddressSection {
	if grouping == nil {
		return nil
	}

	cache := grouping.cache
	if cache == nil { // zero-valued
		return zeroEmbeddedIPv6AddressSection
	}

	return cache.mixed.embeddedIPv6Section
}

// GetIPv4AddressSection returns the ending IPv4 section of the grouping.
func (grouping *IPv6v4MixedAddressGrouping) GetIPv4AddressSection() *IPv4AddressSection {
	if grouping == nil {
		return nil
	}

	cache := grouping.cache
	if cache == nil { // zero-valued
		return zeroIPv4AddressSection
	}

	return cache.mixed.embeddedIPv4Section
}

// GetCount returns the count of possible distinct values for this item.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions,
// or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (grouping *IPv6v4MixedAddressGrouping) GetCount() *big.Int {
	if grouping == nil {
		return bigZero()
	}

	cnt := grouping.GetIPv6AddressSection().GetCount()

	return cnt.Mul(cnt, grouping.GetIPv4AddressSection().GetCount())
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

func compressMixedSect(m address_string.MixedCompressionOptions, addressSection *IPv6AddressSection) bool {
	switch m {
	case address_string.AllowMixedCompression:
		return true
	case address_string.NoMixedCompression:
		return false
	case address_string.MixedCompressionNoHost:
		return !addressSection.IsPrefixed()
	case address_string.MixedCompressionCoveredByHost:
		if addressSection.IsPrefixed() {
			mixedDistance := IPv6MixedOriginalSegmentCount
			mixedCount := addressSection.GetSegmentCount() - mixedDistance
			if mixedCount > 0 {
				return (BitCount(mixedDistance) * addressSection.GetBitsPerSegment()) >= addressSection.getNetworkPrefixLen().bitCount()
			}
		}
		return true
	default:
		return true
	}
}

func getIPv6MaxValue(segmentCount int) *big.Int {
	return new(big.Int).Set(ipv6MaxValues[segmentCount])
}

func maxInt(segCount int) *big.Int {
	res := new(big.Int).SetUint64(1)
	return res.Lsh(res, 16*uint(segCount)).Sub(res, bigOneConst())
}

func createMixedAddressGrouping(divisions []*AddressDivision, mixedCache *mixedCache) *IPv6v4MixedAddressGrouping {
	grouping := &IPv6v4MixedAddressGrouping{
		addressDivisionGroupingInternal: addressDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions: standardDivArray(divisions),
				addrType:  ipv6v4MixedType,
				cache:     &valueCache{mixed: mixedCache},
			},
		},
	}
	ipv6Section := mixedCache.embeddedIPv6Section
	ipv4Section := mixedCache.embeddedIPv4Section
	grouping.isMult = ipv6Section.isMultiple() || ipv4Section.isMultiple()
	if ipv6Section.IsPrefixed() {
		grouping.prefixLength = ipv6Section.getPrefixLen()
	} else if ipv4Section.IsPrefixed() {
		grouping.prefixLength = cacheBitCount(ipv6Section.GetBitCount() + ipv4Section.getPrefixLen().bitCount())
	}
	return grouping
}

func newIPv6v4MixedGrouping(ipv6Section *EmbeddedIPv6AddressSection, ipv4Section *IPv4AddressSection) *IPv6v4MixedAddressGrouping {
	ipv6Len := ipv6Section.GetSegmentCount()
	ipv4Len := ipv4Section.GetSegmentCount()
	allSegs := make([]*AddressDivision, ipv6Len+ipv4Len)
	ipv6Section.copySubDivisions(0, ipv6Len, allSegs)
	ipv4Section.copySubDivisions(0, ipv4Len, allSegs[ipv6Len:])
	grouping := createMixedAddressGrouping(allSegs, &mixedCache{
		embeddedIPv6Section: ipv6Section,
		embeddedIPv4Section: ipv4Section,
	})
	return grouping
}

func newIPv6Section(segments []*AddressDivision) *IPv6AddressSection {
	return createIPv6Section(segments)
}

func newIPv6SectionFromMixed(segments []*AddressDivision) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.initMultiple()
	return
}

// NewIPv6PrefixedSection constructs an IPv6 address or subnet section from the given segments and prefix length.
func NewIPv6PrefixedSection(segments []*IPv6AddressSegment, prefixLen PrefixLen) *IPv6AddressSection {
	return createIPv6SectionFromSegs(segments, prefixLen)
}

// NewIPv6SectionFromPrefixedUint64 constructs an IPv6 address or prefix block section of the given segment count from the given values and prefix length.
func NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes uint64, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = IPv6SegmentCount
	}

	segments := createSegmentsUint64(
		segmentCount,
		highBytes,
		lowBytes,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		ipv6Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv6Section(segments)

	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), false, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
	} else {
		res.cache.uint128Cache = &uint128Cache{high: highBytes, low: lowBytes}
	}

	return
}

func toSegmentsFromWords(words []big.Word, segmentCount int, prefixLength PrefixLen) (segments []*AddressDivision, err address_error.AddressValueError) {
	var currentWord big.Word
	wordBitSize := bits.UintSize
	segments = createSegmentArray(segmentCount)
	segmentsPerWord := wordBitSize >> ipv6BitsToSegmentBitshift
	wordLen := len(words)
	if wordLen > 0 {
		currentWord = words[0]
	}

	// start with little end
	for wordIndex, wordSegmentIndex, segmentIndex := 0, 0, segmentCount-1; ; segmentIndex-- {
		var value IPv6SegInt
		if wordIndex < wordLen {
			value = IPv6SegInt(currentWord)
			currentWord >>= uint(IPv6BitsPerSegment)
			wordSegmentIndex++
		}

		segmentPrefixLength := getSegmentPrefixLength(IPv6BitsPerSegment, prefixLength, segmentIndex)
		seg := NewIPv6PrefixedSegment(value, segmentPrefixLength)
		segments[segmentIndex] = seg.ToDiv()

		if wordSegmentIndex == segmentsPerWord {
			wordSegmentIndex = 0
			wordIndex++
			if wordIndex < wordLen {
				currentWord = words[wordIndex]
			}
		}

		if segmentIndex == 0 {
			// any remaining words should be zero
			isErr := currentWord != 0
			switch isErr {
			case true:
				err = &addressValueError{
					addressError: addressError{key: "ipaddress.error.exceeds.size"},
					val:          int(words[wordIndex]),
				}
			case false:
				for wordIndex++; wordIndex < wordLen; wordIndex++ {
					if isErr = words[wordIndex] != 0; isErr {
						break
					}
				}
			}
			break
		}
	}
	return
}

// NewIPv6SectionFromUint64 constructs an IPv6 address section of the given segment count from the given values.
func NewIPv6SectionFromUint64(highBytes, lowBytes uint64, segmentCount int) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes, segmentCount, nil)
}

func newIPv6SectionFromWords(words []big.Word, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err address_error.AddressValueError) {
	if segmentCount < 0 {
		wordBitSize := bits.UintSize
		segmentCount = (len(words) * wordBitSize) >> 4
	}

	segments, err := toSegmentsFromWords(
		words,
		segmentCount,
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
		}
	}
	return
}

// NewIPv6SectionFromBigInt creates an IPv6 address section from the given big integer,
// returning an error if the value is too large for the given number of segments.
func NewIPv6SectionFromBigInt(val *big.Int, segmentCount int) (res *IPv6AddressSection, err address_error.AddressValueError) {
	if val.Sign() < 0 {
		err = &addressValueError{
			addressError: addressError{key: "ipaddress.error.negative"},
		}
		return
	}
	return newIPv6SectionFromWords(val.Bits(), segmentCount, nil, false)
}

// NewIPv6SectionFromPrefixedBigInt creates an IPv6 address or prefix block section from the given big integer,
// returning an error if the value is too large for the given number of segments.
func NewIPv6SectionFromPrefixedBigInt(val *big.Int, segmentCount int, prefixLen PrefixLen) (res *IPv6AddressSection, err address_error.AddressValueError) {
	if val.Sign() < 0 {
		err = &addressValueError{
			addressError: addressError{key: "ipaddress.error.negative"},
		}
		return
	}
	return newIPv6SectionFromWords(val.Bits(), segmentCount, prefixLen, false)
}

// NewIPv6SectionFromBytes constructs an IPv6 address from the given byte slice.
// The segment count is determined by the slice length, even if the segment count exceeds 8 segments.
func NewIPv6SectionFromBytes(bytes []byte) *IPv6AddressSection {
	res, _ := newIPv6SectionFromBytes(bytes, (len(bytes)+1)>>1, nil, false)
	return res
}

// NewIPv6SectionFromPrefixedBytes constructs an IPv6 address or prefix block from the given byte slice and prefix length.
// It allows you to specify the segment count for the supplied bytes.
// If the slice is too large for the given number of segments, an error is returned, although leading zeros are tolerated.
func NewIPv6SectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection, err address_error.AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv6SectionFromPrefixedSingle(vals, upperVals IPv6SegmentValueProvider, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}

	segments, isMultiple := createSegments(
		WrapIPv6SegmentValueProvider(vals),
		WrapIPv6SegmentValueProvider(upperVals),
		segmentCount,
		IPv6BitsPerSegment,
		ipv6Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv6Section(segments)
	res.isMult = isMultiple

	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
	}

	return
}

// NewIPv6SectionFromPrefixedRange constructs an IPv6 subnet section of the given segment count from the given values and prefix length.
func NewIPv6SectionFromPrefixedRange(vals, upperVals IPv6SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	return newIPv6SectionFromPrefixedSingle(vals, upperVals, segmentCount, prefixLength, false)
}

// NewIPv6SectionFromVals constructs an IPv6 address section of the given segment count from the given values.
func NewIPv6SectionFromVals(vals IPv6SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRange(vals, nil, segmentCount, nil)
	return
}

// NewIPv6SectionFromPrefixedVals constructs an IPv6 address or prefix block section of the given segment count from the given values and prefix length.
func NewIPv6SectionFromPrefixedVals(vals IPv6SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedRange(vals, nil, segmentCount, prefixLength)
}

// NewIPv6SectionFromRange constructs an IPv6 subnet section of the given segment count from the given values.
func NewIPv6SectionFromRange(vals, upperVals IPv6SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRange(vals, upperVals, segmentCount, nil)
	return
}

func toIPv6SegmentsFromEUI(
	segments []*AddressDivision,
	ipv6StartIndex int, // the index into the IPv6 segment array to put the MAC-based IPv6 segments
	eui *MACAddressSection, // must be full 6 or 8 mac sections
	prefixLength PrefixLen) address_error.IncompatibleAddressError {
	var seg3, seg4 *MACAddressSegment
	var err address_error.IncompatibleAddressError
	euiSegmentIndex := 0
	seg0 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg1 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg2 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	isExtended := eui.GetSegmentCount() == ExtendedUniqueIdentifier64SegmentCount
	if isExtended {
		seg3 = eui.GetSegment(euiSegmentIndex)
		euiSegmentIndex++
		if !seg3.matches(0xff) {
			return &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
		}
		seg4 = eui.GetSegment(euiSegmentIndex)
		euiSegmentIndex++
		if !seg4.matches(0xfe) {
			return &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
		}
	} else {
		seg3 = ffMACSeg
		seg4 = feMACSeg
	}

	var currentPrefix PrefixLen
	seg5 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg6 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg7 := eui.GetSegment(euiSegmentIndex)
	if prefixLength != nil {
		//since the prefix comes from the ipv6 section and not the MAC section, any segment prefix for the MAC section is 0 or nil
		//prefixes across segments have the pattern: nil, nil, ..., nil, 0-16, 0, 0, ..., 0
		//So if the overall prefix is 0, then the prefix of every segment is 0
		currentPrefix = cacheBitCount(0)
	}

	var seg *IPv6AddressSegment
	if seg, err = seg0.JoinAndFlip2ndBit(seg1, currentPrefix); /* only this first one gets the flipped bit */ err == nil {
		segments[ipv6StartIndex] = seg.ToDiv()
		ipv6StartIndex++
		if seg, err = seg2.Join(seg3, currentPrefix); err == nil {
			segments[ipv6StartIndex] = seg.ToDiv()
			ipv6StartIndex++
			if seg, err = seg4.Join(seg5, currentPrefix); err == nil {
				segments[ipv6StartIndex] = seg.ToDiv()
				ipv6StartIndex++
				if seg, err = seg6.Join(seg7, currentPrefix); err == nil {
					segments[ipv6StartIndex] = seg.ToDiv()
					return nil
				}
			}
		}
	}
	return err
}

// NewIPv6SectionFromMAC constructs an IPv6 address section from a modified EUI-64 (Extended Unique Identifier) MAC address.
//
// If the supplied MAC address section is an 8-byte EUI-64, then it must match the required EUI-64 format of "xx-xx-ff-fe-xx-xx"
// with the "ff-fe" section in the middle.
//
// If the supplied MAC address section is a 6-byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted when converting to IPv6.
//
// The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
//
// The error is IncompatibleAddressError when unable to join two MAC segments, at least one with ranged values, into an equivalent IPV6 segment range.
func NewIPv6SectionFromMAC(eui *MACAddress) (res *IPv6AddressSection, err address_error.IncompatibleAddressError) {
	segments := createSegmentArray(4)
	if err = toIPv6SegmentsFromEUI(segments, 0, eui.GetSection(), nil); err != nil {
		return
	}

	res = createIPv6Section(segments)
	res.isMult = eui.isMultiple()
	return
}
