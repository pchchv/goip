package goip

import (
	"math/big"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

var (
	rangeWildcard                 = new(address_string.WildcardsBuilder).ToWildcards()
	allWildcards                  = new(address_string.WildcardOptionsBuilder).SetWildcardOptions(address_string.WildcardsAll).ToOptions()
	wildcardsRangeOnlyNetworkOnly = new(address_string.WildcardOptionsBuilder).SetWildcards(rangeWildcard).ToOptions()
	allSQLWildcards               = new(address_string.WildcardOptionsBuilder).SetWildcardOptions(address_string.WildcardsAll).SetWildcards(
		new(address_string.WildcardsBuilder).SetWildcard(SegmentSqlWildcardStr).SetSingleWildcard(SegmentSqlSingleWildcardStr).ToWildcards()).ToOptions()
)

type ipAddressSectionInternal struct {
	addressSectionInternal
}

func (section *ipAddressSectionInternal) getNetworkPrefixLen() PrefixLen {
	return section.prefixLength
}

// GetNetworkPrefixLen returns the prefix length or nil if there is no prefix length.
// This is equivalent to GetPrefixLen.
//
// A prefix length indicates the number of bits in the initial part of the address item that make up the prefix.
//
// A prefix is a part of an address item that is not specific to a given address,
// but is common to a group of such items, such as the subnet of a CIDR prefix block.
func (section *ipAddressSectionInternal) GetNetworkPrefixLen() PrefixLen {
	return section.getNetworkPrefixLen().copy()
}

// GetBlockMaskPrefixLen returns the prefix length if this address section is equivalent to the mask for a CIDR prefix block.
// Otherwise, it returns nil.
// A CIDR network mask is an address section with all ones in the network section and then all zeros in the host section.
// A CIDR host mask is an address section with all zeros in the network section and then all ones in the host section.
// The prefix length is the bit-length of the network section.
//
// Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length of this instance,
// indicating the network and host section of this address section.
// The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
// section of any other address.  Therefore the two values can be different values, or one can be nil while the other is not.
//
// This method applies only to the lower value of the range if this section represents multiple values.
func (section *ipAddressSectionInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	cache := section.cache
	if cache == nil {
		return nil // no prefix
	}
	cachedMaskLens := (*maskLenSetting)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.cachedMaskLens))))
	if cachedMaskLens == nil {
		networkMaskLen, hostMaskLen := section.checkForPrefixMask()
		cachedMaskLens = &maskLenSetting{networkMaskLen, hostMaskLen}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedMaskLens))
		atomicStorePointer(dataLoc, unsafe.Pointer(cachedMaskLens))
	}
	if network {
		return cachedMaskLens.networkMaskLen
	}
	return cachedMaskLens.hostMaskLen
}

func (section *ipAddressSectionInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	count := section.GetSegmentCount()
	if count == 0 {
		return
	}
	firstSeg := section.GetSegment(0)
	checkingNetworkFront, checkingHostFront := true, true
	var checkingNetworkBack, checkingHostBack bool
	var prefixedSeg int
	prefixedSegPrefixLen := BitCount(0)
	maxVal := firstSeg.GetMaxValue()
	for i := 0; i < count; i++ {
		seg := section.GetSegment(i)
		val := seg.GetSegmentValue()
		if val == 0 {
			if checkingNetworkFront {
				prefixedSeg = i
				checkingNetworkFront, checkingNetworkBack = false, true
			} else if !checkingHostFront && !checkingNetworkBack {
				return
			}
			checkingHostBack = false
		} else if val == maxVal {
			if checkingHostFront {
				prefixedSeg = i
				checkingHostFront, checkingHostBack = false, true
			} else if !checkingHostBack && !checkingNetworkFront {
				return
			}
			checkingNetworkBack = false
		} else {
			segNetworkMaskLen, segHostMaskLen := seg.checkForPrefixMask()
			if segNetworkMaskLen != nil {
				if checkingNetworkFront {
					prefixedSegPrefixLen = segNetworkMaskLen.bitCount()
					checkingNetworkBack = true
					checkingHostBack = false
					prefixedSeg = i
				} else {
					return
				}
			} else if segHostMaskLen != nil {
				if checkingHostFront {
					prefixedSegPrefixLen = segHostMaskLen.bitCount()
					checkingHostBack = true
					checkingNetworkBack = false
					prefixedSeg = i
				} else {
					return
				}
			} else {
				return
			}
			checkingNetworkFront, checkingHostFront = false, false
		}
	}
	if checkingNetworkFront {
		// all ones
		networkMaskLen = cacheBitCount(section.GetBitCount())
		hostMaskLen = cacheBitCount(0)
	} else if checkingHostFront {
		// all zeros
		hostMaskLen = cacheBitCount(section.GetBitCount())
		networkMaskLen = cacheBitCount(0)
	} else if checkingNetworkBack {
		// ending in zeros, network mask
		networkMaskLen = getNetworkPrefixLen(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	} else if checkingHostBack {
		// ending in ones, host mask
		hostMaskLen = getNetworkPrefixLen(firstSeg.GetBitCount(), prefixedSegPrefixLen, prefixedSeg)
	}
	return
}

// GetBitsPerSegment returns the number of bits comprising each segment in this section.  Segments in the same address section are equal length.
func (section *ipAddressSectionInternal) GetBitsPerSegment() BitCount {
	return section.addressSectionInternal.GetBitsPerSegment()
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.  Segments in the same address section are equal length.
func (section *ipAddressSectionInternal) GetBytesPerSegment() int {
	return section.addressSectionInternal.GetBytesPerSegment()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (section *ipAddressSectionInternal) GetSegment(index int) *IPAddressSegment {
	return section.getDivision(index).ToIP()
}

// ForEachSegment visits each segment in order from most-significant to least,
// the most significant with index 0, calling the given function for each,
// terminating early if the function returns true.
// Returns the number of visited segments.
func (section *ipAddressSectionInternal) ForEachSegment(consumer func(segmentIndex int, segment *IPAddressSegment) (stop bool)) int {
	divArray := section.getDivArray()
	if divArray != nil {
		for i, div := range divArray {
			if consumer(i, div.ToIP()) {
				return i + 1
			}
		}
	}
	return len(divArray)
}

// GetIPVersion returns the IP version of this IP address section.
func (section *ipAddressSectionInternal) GetIPVersion() IPVersion {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4
	} else if addrType.isIPv6() {
		return IPv6
	}
	return IndeterminateIPVersion
}

// IncludesZeroHostLen returns whether the address section contains an individual section with a host of zero, a section for which all bits past the given prefix length are zero.
func (section *ipAddressSectionInternal) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section, networkPrefixLength)
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	divCount := section.GetSegmentCount()
	for i := prefixedSegmentIndex; i < divCount; i++ {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		mask := div.GetSegmentHostMask(segmentPrefixLength.bitCount())
		if (mask & div.GetSegmentValue()) != 0 {
			return false
		}
		for i++; i < divCount; i++ {
			div = section.GetSegment(i)
			if !div.includesZero() {
				return false
			}
		}
	}
	return true
}

// IncludesMaxHost returns whether the address section contains an individual address section with a host of all one-bits.
// If the address section has no prefix length it returns false.
// If the prefix length matches the bit count, then it returns true.
//
// Otherwise, it checks whether it contains an individual address section for which all bits past the prefix are one.
func (section *ipAddressSectionInternal) IncludesMaxHost() bool {
	networkPrefixLength := section.getPrefixLen()
	return networkPrefixLength != nil && section.IncludesMaxHostLen(networkPrefixLength.bitCount())
}

// IncludesMaxHostLen returns whether the address section contains an individual address section with a host of all one-bits,
// an address section for which all bits past the given prefix length are all ones.
func (section *ipAddressSectionInternal) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	networkPrefixLength = checkSubnet(section, networkPrefixLength)
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	divCount := section.GetSegmentCount()
	for i := prefixedSegmentIndex; i < divCount; i++ {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		if segmentPrefixLength != nil {
			mask := div.GetSegmentHostMask(segmentPrefixLength.bitCount())
			if (mask & div.getUpperSegmentValue()) != mask {
				return false
			}
			for i++; i < divCount; i++ {
				div = section.GetSegment(i)
				if !div.includesMax() {
					return false
				}
			}
		}
	}
	return true
}

// IsSingleNetwork returns whether the network section of the address,
// the prefix, consists of a single value.
//
// If it has no prefix length, it returns true if not multiple,
// if it contains only a single individual address section.
func (section *ipAddressSectionInternal) IsSingleNetwork() bool {
	networkPrefixLength := section.getNetworkPrefixLen()
	if networkPrefixLength == nil {
		return !section.isMultiple()
	}

	prefLen := networkPrefixLength.bitCount()
	if prefLen >= section.GetBitCount() {
		return !section.isMultiple()
	}

	bitsPerSegment := section.GetBitsPerSegment()
	prefixedSegmentIndex := getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < 0 {
		return true
	}

	for i := 0; i < prefixedSegmentIndex; i++ {
		if section.getDivision(i).isMultiple() {
			return false
		}
	}

	div := section.GetSegment(prefixedSegmentIndex)
	divPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
	shift := bitsPerSegment - divPrefLen.bitCount()
	return (div.GetSegmentValue() >> uint(shift)) == (div.GetUpperSegmentValue() >> uint(shift))
}

// IsMaxHost returns whether this section has a prefix length and if so,
// whether the host is all all one-bits, the max value, for all individual sections in this address section.
//
// If the host section is zero length (there are zero host bits), IsMaxHost returns true.
func (section *ipAddressSectionInternal) IsMaxHost() bool {
	if !section.isPrefixed() {
		return false
	}
	return section.IsMaxHostLen(section.getNetworkPrefixLen().bitCount())
}

// IsMaxHostLen returns whether the host host is all one-bits,
// the max value, for all individual sections in this address section,
// for the given prefix length, the host being the bits following the prefix.
//
// If the host section is zero length (there are zero host bits), IsMaxHostLen returns true.
func (section *ipAddressSectionInternal) IsMaxHostLen(prefLen BitCount) bool {
	divCount := section.GetSegmentCount()
	if divCount == 0 {
		return true
	} else if prefLen < 0 {
		prefLen = 0
	}

	bytesPerSegment := section.GetBytesPerSegment()
	bitsPerSegment := section.GetBitsPerSegment()
	// Note: 1.2.3.4/32 has a max host
	prefixedSegmentIndex := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
	if prefixedSegmentIndex < divCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
		i := prefixedSegmentIndex
		div := section.GetSegment(i)
		mask := div.GetSegmentHostMask(segmentPrefixLength.bitCount())
		if div.isMultiple() || (mask&div.getSegmentValue()) != mask {
			return false
		}
		i++
		for ; i < divCount; i++ {
			div = section.GetSegment(i)
			if !div.IsMax() {
				return false
			}
		}
	}
	return true
}

// IsZeroHost returns whether this section has a prefix length and if so,
// whether the host section is always zero for all individual sections in this address section.
//
// If the host section is zero length (there are zero host bits), IsZeroHost returns true.
func (section *ipAddressSectionInternal) IsZeroHost() bool {
	if !section.isPrefixed() {
		return false
	}
	return section.IsZeroHostLen(section.getNetworkPrefixLen().bitCount())
}

// IsZeroHostLen returns whether the host section is always zero for all individual sections in this address section,
// for the given prefix length.
//
// If the host section is zero length (there are zero host bits), IsZeroHostLen returns true.
func (section *ipAddressSectionInternal) IsZeroHostLen(prefLen BitCount) bool {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return true
	} else if prefLen < 0 {
		prefLen = 0
	}
	bitsPerSegment := section.GetBitsPerSegment()
	// Note: 1.2.3.4/32 has a zero host
	prefixedSegmentIndex := getHostSegmentIndex(prefLen, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex < segmentCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
		i := prefixedSegmentIndex
		div := section.GetSegment(i)
		if div.isMultiple() || (div.GetSegmentHostMask(segmentPrefixLength.bitCount())&div.getSegmentValue()) != 0 {
			return false
		}
		for i++; i < segmentCount; i++ {
			div := section.GetSegment(i)
			if !div.IsZero() {
				return false
			}
		}
	}
	return true
}

func (section *ipAddressSectionInternal) adjustPrefixLength(adjustment BitCount, withZeros bool) (*IPAddressSection, address_error.IncompatibleAddressError) {
	if adjustment == 0 && section.isPrefixed() {
		return section.toIPAddressSection(), nil
	}
	prefix := section.getAdjustedPrefix(adjustment)
	sec, err := section.setPrefixLength(prefix, withZeros)
	return sec.ToIP(), err
}

func (section *ipAddressSectionInternal) adjustPrefixLen(adjustment BitCount) *IPAddressSection {
	res, _ := section.adjustPrefixLength(adjustment, false)
	return res
}

func (section *ipAddressSectionInternal) adjustPrefixLenZeroed(adjustment BitCount) (*IPAddressSection, address_error.IncompatibleAddressError) {
	return section.adjustPrefixLength(adjustment, true)
}

func (section *ipAddressSectionInternal) checkSectionCount(other *IPAddressSection) address_error.SizeMismatchError {
	if other.GetSegmentCount() < section.GetSegmentCount() {
		return &sizeMismatchError{incompatibleAddressError{addressError{key: "ipaddress.error.sizeMismatch"}}}
	}
	return nil
}

func (section *ipAddressSectionInternal) matchesWithMask(other *IPAddressSection, mask *IPAddressSection) bool {
	if err := section.checkSectionCount(other); err != nil {
		return false
	} else if err := section.checkSectionCount(mask); err != nil {
		return false
	}

	divCount := section.GetSegmentCount()
	for i := 0; i < divCount; i++ {
		seg := section.GetSegment(i)
		maskSegment := mask.GetSegment(i)
		otherSegment := other.GetSegment(i)
		if !seg.MatchesValsWithMask(
			otherSegment.getSegmentValue(),
			otherSegment.getUpperSegmentValue(),
			maskSegment.getSegmentValue()) {
			return false
		}
	}

	return true
}

func (section *ipAddressSectionInternal) createDiffSection(seg *IPAddressSegment, lower SegInt, upper SegInt, diffIndex int, intersectingValues []*AddressDivision) *IPAddressSection {
	segCount := section.GetSegmentCount()
	segments := createSegmentArray(segCount)

	for j := 0; j < diffIndex; j++ {
		segments[j] = intersectingValues[j]
	}

	diff := createAddressDivision(seg.deriveNewMultiSeg(lower, upper, nil))
	segments[diffIndex] = diff

	for j := diffIndex + 1; j < segCount; j++ {
		segments[j] = section.getDivision(j)
	}

	return deriveIPAddressSection(section.toIPAddressSection(), segments)
}

func (section *ipAddressSectionInternal) toIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *ipAddressSectionInternal) getNetworkSectionLen(networkPrefixLength BitCount) *IPAddressSection {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection()
	}

	var newSegments []*AddressDivision
	bitsPerSegment := section.GetBitsPerSegment()
	networkPrefixLength = checkBitCount(networkPrefixLength, section.GetBitCount())
	prefixedSegmentIndex := getNetworkSegmentIndex(networkPrefixLength, section.GetBytesPerSegment(), bitsPerSegment)
	if prefixedSegmentIndex >= 0 {
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex) // prefixedSegmentIndex of -1 already handled
		lastSeg := section.GetSegment(prefixedSegmentIndex)
		prefBits := segPrefLength.bitCount()
		mask := ^SegInt(0) << uint(bitsPerSegment-prefBits)
		lower, upper := lastSeg.getSegmentValue()&mask, lastSeg.getUpperSegmentValue()|^mask
		networkSegmentCount := prefixedSegmentIndex + 1
		if networkSegmentCount == segmentCount && segsSame(segPrefLength, lastSeg.GetSegmentPrefixLen(), lower, lastSeg.getSegmentValue(), upper, lastSeg.getUpperSegmentValue()) {
			// the segment count and prefixed segment matches
			return section.toIPAddressSection()
		}
		newSegments = createSegmentArray(networkSegmentCount)
		section.copySubDivisions(0, prefixedSegmentIndex, newSegments)
		newSegments[prefixedSegmentIndex] = createAddressDivision(lastSeg.deriveNewMultiSeg(lower, upper, segPrefLength))
	} else {
		newSegments = createSegmentArray(0)
	}

	return deriveIPAddressSectionPrefLen(section.toIPAddressSection(), newSegments, cacheBitCount(networkPrefixLength))
}

func (section *ipAddressSectionInternal) getHostSectionLen(networkPrefixLength BitCount) *IPAddressSection {
	segmentCount := section.GetSegmentCount()
	if segmentCount == 0 {
		return section.toIPAddressSection()
	}

	var prefLen PrefixLen
	var newSegments []*AddressDivision
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	networkPrefixLength = checkBitCount(networkPrefixLength, section.GetBitCount())
	prefixedSegmentIndex := getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	if prefixedSegmentIndex < segmentCount {
		firstSeg := section.GetSegment(prefixedSegmentIndex)
		segPrefLength := getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, prefixedSegmentIndex)
		prefLen = segPrefLength
		prefBits := segPrefLength.bitCount()
		// mask the boundary segment
		mask := ^(^SegInt(0) << uint(bitsPerSegment-prefBits))
		divLower := uint64(firstSeg.getDivisionValue())
		divUpper := uint64(firstSeg.getUpperDivisionValue())
		divMask := uint64(mask)
		maxVal := uint64(^SegInt(0))
		masker := MaskRange(divLower, divUpper, divMask, maxVal)
		lower, upper := masker.GetMaskedLower(divLower, divMask), masker.GetMaskedUpper(divUpper, divMask)
		segLower, segUpper := SegInt(lower), SegInt(upper)

		if prefixedSegmentIndex == 0 && segsSame(segPrefLength, firstSeg.GetSegmentPrefixLen(), segLower, firstSeg.getSegmentValue(), segUpper, firstSeg.getUpperSegmentValue()) {
			// the segment count and prefixed segment matches
			return section.toIPAddressSection()
		}

		hostSegmentCount := segmentCount - prefixedSegmentIndex
		newSegments = createSegmentArray(hostSegmentCount)
		newSegments[0] = createAddressDivision(firstSeg.deriveNewMultiSeg(segLower, segUpper, segPrefLength))

		// the remaining segments each must have zero-segment prefix length
		var zeroPrefixIndex int

		if section.isPrefixed() {
			zeroPrefixIndex = getNetworkSegmentIndex(section.GetPrefixLen().bitCount(), bytesPerSegment, bitsPerSegment) + 1
		} else {
			zeroPrefixIndex = segmentCount
		}

		zeroPrefixIndex -= prefixedSegmentIndex
		zeroPrefixIndex = max(zeroPrefixIndex, 1)
		for i := 1; i < zeroPrefixIndex; i++ {
			seg := section.GetSegment(prefixedSegmentIndex + i)
			newSegments[i] = createAddressDivision(seg.derivePrefixed(cacheBitCount(0)))
		}

		// the rest already have zero-segment prefix length, just copy them
		section.copySubDivisions(prefixedSegmentIndex+zeroPrefixIndex, prefixedSegmentIndex+hostSegmentCount, newSegments[zeroPrefixIndex:])
	} else {
		prefLen = cacheBitCount(0)
		newSegments = createSegmentArray(0)
	}

	return deriveIPAddressSectionPrefLen(section.toIPAddressSection(), newSegments, prefLen)
}

// getSubnetSegments called by methods to adjust/remove/set prefix length,
// masking methods, zero host and zero network methods
func (section *ipAddressSectionInternal) getSubnetSegments(
	startIndex int,
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt,
) (*IPAddressSection, address_error.IncompatibleAddressError) {
	newSect, err := section.addressSectionInternal.getSubnetSegments(startIndex, networkPrefixLength, verifyMask, segProducer, segmentMaskProducer)
	return newSect.ToIP(), err
}

func (section *ipAddressSectionInternal) getNetwork() IPAddressNetwork {
	if addrType := section.getAddrType(); addrType.isIPv4() {
		return ipv4Network
	} else if addrType.isIPv6() {
		return ipv6Network
	}
	return nil
}

// Wrap wraps this IP address section, returning a WrappedIPAddressSection,
// an implementation of ExtendedIPSegmentSeries that can be used to write code that works with both IP addresses and IP address sections.
// Wrap can be called with a nil receiver, wrapping a nil address section.
func (section *ipAddressSectionInternal) Wrap() WrappedIPAddressSection {
	return wrapIPSection(section.toIPAddressSection())
}

// WrapSection wraps this IP address section, returning a WrappedAddressSection,
//
//	an implementation of ExtendedSegmentSeries that can be used to write code that works with both addresses and address sections.
//
// WrapSection can be called with a nil receiver, wrapping a nil address section.
func (section *ipAddressSectionInternal) WrapSection() WrappedAddressSection {
	return wrapSection(section.toAddressSection())
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (section *ipAddressSectionInternal) GetBitCount() BitCount {
	return section.addressSectionInternal.GetBitCount()
}

// GetByteCount returns the number of bytes required for each value comprising this address item.
func (section *ipAddressSectionInternal) GetByteCount() int {
	return section.addressSectionInternal.GetByteCount()
}

// IsZero returns whether this section matches exactly the value of zero.
func (section *ipAddressSectionInternal) IsZero() bool {
	return section.addressSectionInternal.IsZero()
}

// IncludesZero returns whether this section includes the value of zero within its range.
func (section *ipAddressSectionInternal) IncludesZero() bool {
	return section.addressSectionInternal.IncludesZero()
}

// IsMax returns whether this section matches exactly the maximum possible value,
// the value whose bits are all ones.
func (section *ipAddressSectionInternal) IsMax() bool {
	return section.addressSectionInternal.IsMax()
}

// IncludesMax returns whether this section includes the max value,
// the value whose bits are all ones, within its range.
func (section *ipAddressSectionInternal) IncludesMax() bool {
	return section.addressSectionInternal.IncludesMax()
}

// IsFullRange returns whether this address item represents all possible values attainable by an address item of this type.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (section *ipAddressSectionInternal) IsFullRange() bool {
	return section.addressSectionInternal.IsFullRange()
}

// GetSequentialBlockIndex gets the minimal segment index for which all following segments are full-range blocks.
//
// The segment at this index is not a full-range block itself, unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full address section to be sequential, the preceding segments must be single-valued.
func (section *ipAddressSectionInternal) GetSequentialBlockIndex() int {
	return section.addressSectionInternal.GetSequentialBlockIndex()
}

// GetSequentialBlockCount provides the count of elements from the sequential block iterator, the minimal number of sequential address sections that comprise this address section.
func (section *ipAddressSectionInternal) GetSequentialBlockCount() *big.Int {
	return section.addressSectionInternal.GetSequentialBlockCount()
}

// ContainsPrefixBlock returns whether the values of this item contains the block of values for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (section *ipAddressSectionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return section.addressSectionInternal.ContainsPrefixBlock(prefixLen)
}

// IsPrefixBlock returns whether the given series of address segments has
// a prefix length and whether it includes the block associated with its prefix length.
// If the prefix length matches the bit count, true is returned.
//
// This method differs from the ContainsPrefixBlock method in that it returns false if
// the series has no prefix length or the prefix length differs from
// the prefix length for which the ContainsPrefixBlock returns true.
func (section *ipAddressSectionInternal) IsPrefixBlock() bool {
	return section.addressSectionInternal.IsPrefixBlock()
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this section includes a block of all values for that prefix length.
//
// If the entire range can be described in this way, this method returns the same value as GetPrefixLenForSingleBlock.
//
// For the returned prefix length, there can be either a single prefix or multiple possible prefix values in this block.
// To avoid the case of multiple prefix values, use the GetPrefixLenForSingleBlock.
//
// If this section represents a single value, a bit count is returned.
func (section *ipAddressSectionInternal) GetMinPrefixLenForBlock() BitCount {
	return section.addressSectionInternal.GetMinPrefixLenForBlock()
}

// GetValue returns the lowest individual address section in this address section as an integer value.
func (section *ipAddressSectionInternal) GetValue() *big.Int {
	return section.addressSectionInternal.GetValue()
}

// GetUpperValue returns the highest individual address section in this address section as an integer value.
func (section *ipAddressSectionInternal) GetUpperValue() *big.Int {
	return section.addressSectionInternal.GetUpperValue()
}

// Bytes returns the lowest individual address section in this address section as a byte slice.
func (section *ipAddressSectionInternal) Bytes() []byte {
	return section.addressSectionInternal.Bytes()
}

// UpperBytes returns the highest individual address section in this address section as a byte slice.
func (section *ipAddressSectionInternal) UpperBytes() []byte {
	return section.addressSectionInternal.UpperBytes()
}

// CopyBytes copies the value of the lowest individual address section in the section into a byte slice.
//
// If the value can fit in the given slice, it is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (section *ipAddressSectionInternal) CopyBytes(bytes []byte) []byte {
	return section.addressSectionInternal.CopyBytes(bytes)
}

// CopyUpperBytes copies the value of the highest individual address in the section into a byte slice.
//
// If the value can fit into the given slice, it is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (section *ipAddressSectionInternal) CopyUpperBytes(bytes []byte) []byte {
	return section.addressSectionInternal.CopyUpperBytes(bytes)
}

// IsSequential returns whether the section represents a range of values that are sequential.
//
// Generally, this means that any segment covering a range of
// values must be followed by segment that are full range, covering all values.
func (section *ipAddressSectionInternal) IsSequential() bool {
	return section.addressSectionInternal.IsSequential()
}

// GetSegmentCount returns the segment/division count.
func (section *ipAddressSectionInternal) GetSegmentCount() int {
	return section.addressSectionInternal.GetSegmentCount()
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (section *ipAddressSectionInternal) GetMaxSegmentValue() SegInt {
	return section.addressSectionInternal.GetMaxSegmentValue()
}

// IncludesZeroHost returns whether the address section contains an individual address section with a host of zero.
// If the address section has no prefix length it returns false.
// If the prefix length matches the bit count, then it returns true.
//
// Otherwise, it checks whether it contains an individual address section for which all bits past the prefix are zero.
func (section *ipAddressSectionInternal) IncludesZeroHost() bool {
	networkPrefixLength := section.getPrefixLen()
	return networkPrefixLength != nil && section.IncludesZeroHostLen(networkPrefixLength.bitCount())
}

// boundariesOnly: whether it is important to us that masking works for all values in the range.
// For example, 1.2.3.2-4/31 cannot be a null host,
// because when applied to bounds we get 1.2.3.2-4/31, and that includes 1.2.3.3/31,
// which does not have a null host. So in this case, we usually get a boundaries_error.IncompatibleAddressError.
// BoundariesOnly as true avoids an exception if we are really only interested in getting the boundaries of the null host,
// and we are not interested in the other values in between.
func (section *ipAddressSectionInternal) createZeroHost(prefLen BitCount, boundariesOnly bool) (*IPAddressSection, address_error.IncompatibleAddressError) {
	mask := section.addrType.getIPNetwork().GetNetworkMask(prefLen)
	return section.getSubnetSegments(
		getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment()),
		cacheBitCount(prefLen),
		!boundariesOnly, //verifyMask
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
}

func (section *ipAddressSectionInternal) createZeroNetwork() *IPAddressSection {
	prefixLength := section.getNetworkPrefixLen()
	mask := section.addrType.getIPNetwork().GetHostMask(prefixLength.bitCount())
	res, _ := section.getSubnetSegments(
		0,
		prefixLength,
		false,
		section.getDivision,
		func(i int) SegInt { return mask.GetSegment(i).GetSegmentValue() })
	return res
}

func (section *ipAddressSectionInternal) withoutPrefixLen() *IPAddressSection {
	if !section.isPrefixed() {
		return section.toIPAddressSection()
	}

	if section.hasNoDivisions() {
		return createIPSection(section.getDivisionsInternal(), nil, section.getAddrType())
	}

	var startIndex int
	maxVal := section.GetMaxSegmentValue()
	existingPrefixLength := section.getPrefixLen().bitCount()
	if existingPrefixLength > 0 {
		bitsPerSegment := section.GetBitsPerSegment()
		bytesPerSegment := section.GetBytesPerSegment()
		startIndex = getNetworkSegmentIndex(existingPrefixLength, bytesPerSegment, bitsPerSegment)
	}

	res, _ := section.getSubnetSegments(
		startIndex,
		nil,
		false,
		func(i int) *AddressDivision {
			return section.getDivision(i)
		},
		func(i int) SegInt {
			return maxVal
		},
	)

	return res
}

// IPAddressSection is the address section of an IP address containing a certain number of consecutive IP address segments.
// It represents a sequence of individual address segments.
// Each segment has the same bit length.
// Behind each address is an address section containing all address segments.
// IPAddressSection objects are immutable.
// This also makes them concurrency-safe.
// Most operations that can be performed on IPAddress instances can also be performed on IPAddressSection instances, and vice versa.
type IPAddressSection struct {
	ipAddressSectionInternal
}

// ToSectionBase converts to an AddressSection, a polymorphic type usable with all address sections.
// Afterwards, you can convert back with ToIP.
//
// ToSectionBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPAddressSection) ToSectionBase() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

// IsIPv4 returns true if this address section originated as an IPv4 section.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (section *IPAddressSection) IsIPv4() bool { // we allow nil receivers to allow this to be called following a failed converion like ToIP()
	return section != nil && section.matchesIPv4SectionType()
}

// IsIPv6 returns true if this address section originated as an IPv6 section.
// If so, use ToIPv6 to convert back to the IPv6-specific type.
func (section *IPAddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6SectionType()
}

// ToIPv4 converts to an IPv4AddressSection if this section originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPAddressSection) ToIPv4() *IPv4AddressSection {
	if section.IsIPv4() {
		return (*IPv4AddressSection)(section)
	}
	return nil
}

// ToIPv6 converts to an IPv6AddressSection if this section originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *IPAddressSection) ToIPv6() *IPv6AddressSection {
	if section.IsIPv6() {
		return (*IPv6AddressSection)(section)
	}
	return nil
}

// Starting from the first host bit according to the prefix,
// if the section is a sequence of zeros in both low and high values,
// followed by a sequence where low values are zero and high values are 1,
// then the section is a subnet prefix.
//
// Note that this includes sections where hosts are all zeros,
// or sections where hosts are full range of values,
// so the sequence of zeros can be empty and the sequence of
// where low values are zero and high values are 1 can be empty as well.
// However, if they are both empty, then this returns false,
// there must be at least one bit in the sequence.
func isPrefixSubnetDivs(sectionSegments []*AddressDivision, networkPrefixLength BitCount) bool {
	segmentCount := len(sectionSegments)
	if segmentCount == 0 {
		return false
	}

	seg := sectionSegments[0]

	return isPrefixSubnet(
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToSegmentBase().GetSegmentValue()
		},
		func(segmentIndex int) SegInt {
			return sectionSegments[segmentIndex].ToSegmentBase().GetUpperSegmentValue()
		},
		segmentCount,
		seg.GetByteCount(),
		seg.GetBitCount(),
		seg.ToSegmentBase().GetMaxValue(),
		networkPrefixLength,
		zerosOnly)
}

func applyPrefixToSegments(
	sectionPrefixBits BitCount,
	segments []*AddressDivision,
	segmentBitCount BitCount,
	segmentByteCount int,
	segProducer func(*AddressDivision, PrefixLen) *AddressDivision) {
	if sectionPrefixBits != 0 {
		for i := getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount); i < len(segments); i++ {
			pref := getPrefixedSegmentPrefixLength(segmentBitCount, sectionPrefixBits, i)
			if pref != nil {
				segments[i] = segProducer(segments[i], pref)
			}
		}
	}
}

// handles prefix block subnets, and ensures segment prefixes match the section prefix
func assignPrefix(prefixLength PrefixLen, segments []*AddressDivision, res *IPAddressSection, singleOnly, checkPrefixes bool, boundaryBits BitCount) {
	prefLen := prefixLength.bitCount()
	if prefLen < 0 {
		prefLen = 0
	} else if prefLen > boundaryBits {
		prefLen = boundaryBits
		prefixLength = cacheBitCount(boundaryBits)
	} else {
		prefixLength = cachePrefixLen(prefixLength) // use our own cache of prefix lengths so callers cannot overwrite a section's prefix length
	}

	segLen := len(segments)
	if segLen > 0 {
		var segProducer func(*AddressDivision, PrefixLen) *AddressDivision
		applyPrefixSubnet := !singleOnly && isPrefixSubnetDivs(segments, prefLen)
		if applyPrefixSubnet || checkPrefixes {
			if applyPrefixSubnet {
				segProducer = (*AddressDivision).toPrefixedNetworkDivision
			} else {
				segProducer = (*AddressDivision).toPrefixedDivision
			}
			applyPrefixToSegments(
				prefLen,
				segments,
				res.GetBitsPerSegment(),
				res.GetBytesPerSegment(),
				segProducer)
			if applyPrefixSubnet {
				res.isMult = res.isMult || res.GetSegment(segLen-1).isMultiple()
			}
		}
	}

	res.prefixLength = prefixLength
	return
}

func createIPSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *IPAddressSection {
	sect := &IPAddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions:    standardDivArray(segments),
						addrType:     addrType,
						cache:        &valueCache{},
						prefixLength: prefixLength,
					},
				},
			},
		},
	}
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

// Callers to this function have already initialized the segments to have consistent prefix lengths,
// but in here we need to determine what that prefix length might be.
func deriveIPAddressSection(from *IPAddressSection, segments []*AddressDivision) (res *IPAddressSection) {
	res = createIPSection(segments, nil, from.getAddrType())
	res.initMultAndPrefLen()
	return
}

// Callers to this function have already initialized the segments to have prefix lengths corresponding to the supplied argument prefixLength
// So we need only check if multiple and assign the prefix length.
func deriveIPAddressSectionPrefLen(from *IPAddressSection, segments []*AddressDivision, prefixLength PrefixLen) (res *IPAddressSection) {
	res = createIPSection(segments, prefixLength, from.getAddrType())
	res.initMultiple()
	return
}

// createSegmentsUint64 called prior to check for prefix subnet.
// The segments must be created first before that can happen.
func createSegmentsUint64(
	segLen int,
	highBytes,
	lowBytes uint64,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	assignedPrefixLength PrefixLen) []*AddressDivision {
	segmentMask := ^(^SegInt(0) << uint(bitsPerSegment))
	lowSegCount := getHostSegmentIndex(64, bytesPerSegment, bitsPerSegment)
	newSegs := make([]*AddressDivision, segLen)
	lowIndex := segLen - lowSegCount
	if lowIndex < 0 {
		lowIndex = 0
	}

	segmentIndex := segLen - 1
	bytes := lowBytes

	for {
		for {
			segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, assignedPrefixLength, segmentIndex)
			value := segmentMask & SegInt(bytes)
			seg := creator.createSegment(value, value, segmentPrefixLength)
			newSegs[segmentIndex] = seg
			segmentIndex--
			if segmentIndex < lowIndex {
				break
			}
			bytes >>= uint(bitsPerSegment)
		}
		if lowIndex == 0 {
			break
		}
		lowIndex = 0
		bytes = highBytes
	}

	return newSegs
}

// createSegments called prior to check for prefix subnet.
// The segments must be created first before that can happen.
func createSegments(
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, isMultiple bool) {
	segments = createSegmentArray(segmentCount)

	for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
		var value, value2 SegInt
		if lowerValueProvider == nil {
			value = upperValueProvider(segmentIndex)
			value2 = value
		} else {
			value = lowerValueProvider(segmentIndex)
			if upperValueProvider != nil {
				value2 = upperValueProvider(segmentIndex)
				if !isMultiple && value2 != value {
					isMultiple = true

				}
			} else {
				value2 = value
			}
		}
		seg := creator.createSegment(value, value2, segmentPrefixLength)
		segments[segmentIndex] = seg
	}

	return
}

func createIPSectionFromSegs(isIPv4 bool, orig []*IPAddressSegment, prefLen PrefixLen) (result *IPAddressSection) {
	var isMultiple bool
	var newPref PrefixLen
	var divs []*AddressDivision
	segProvider := func(index int) *IPAddressSegment {
		return orig[index]
	}

	if isIPv4 {
		divs, newPref, isMultiple = createDivisionsFromSegs(
			segProvider,
			len(orig),
			ipv4BitsToSegmentBitshift,
			IPv4BitsPerSegment,
			IPv4BytesPerSegment,
			IPv4MaxValuePerSegment,
			zeroIPv4Seg.ToIP(),
			zeroIPv4SegZeroPrefix.ToIP(),
			zeroIPv4SegPrefixBlock.ToIP(),
			prefLen)
		result = createIPv4Section(divs).ToIP()
	} else {
		divs, newPref, isMultiple = createDivisionsFromSegs(
			segProvider,
			len(orig),
			ipv6BitsToSegmentBitshift,
			IPv6BitsPerSegment,
			IPv6BytesPerSegment,
			IPv6MaxValuePerSegment,
			zeroIPv6Seg.ToIP(),
			zeroIPv6SegZeroPrefix.ToIP(),
			zeroIPv6SegPrefixBlock.ToIP(),
			prefLen)
		result = createIPv6Section(divs).ToIP()
	}

	result.prefixLength = newPref
	result.isMult = isMultiple
	return result
}
