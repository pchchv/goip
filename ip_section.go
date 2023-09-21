package goip

import (
	"unsafe"

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
