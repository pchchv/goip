package goip

import (
	"fmt"
	"math/big"
	"strconv"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

var (
	hexPrefixedUppercaseParams = new(address_string.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).SetUppercase(true).ToOptions()
	octal0oPrefixedParams      = new(address_string.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(otherOctalPrefix).ToOptions()
	binaryPrefixedParams       = new(address_string.StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(BinaryPrefix).ToOptions()
	octalPrefixedParams        = new(address_string.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(OctalPrefix).ToOptions()
	hexUppercaseParams         = new(address_string.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetUppercase(true).ToOptions()
	hexPrefixedParams          = new(address_string.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).ToOptions()
	decimalParams              = new(address_string.StringOptionsBuilder).SetRadix(10).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	binaryParams               = new(address_string.StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	octalParams                = new(address_string.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	hexParams                  = new(address_string.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	zeroSection                = createSection(zeroDivs, nil, zeroType)
	otherHexPrefix             = "0X"
	otherOctalPrefix           = "0o"
)

type addressSectionInternal struct {
	addressDivisionGroupingInternal
}

// GetSegmentCount returns the segment count.
func (section *addressSectionInternal) GetSegmentCount() int {
	return section.GetDivisionCount()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.getDivision(index).ToSegmentBase()
}

// Bytes returns the lowest individual address section in this address section as a byte slice.
func (section *addressSectionInternal) Bytes() []byte {
	return section.addressDivisionGroupingInternal.Bytes()
}

// GetBitsPerSegment returns the number of bits comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *addressSectionInternal) GetBitsPerSegment() BitCount {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BitsPerSegment
	} else if addrType.isIPv6() {
		return IPv6BitsPerSegment
	} else if addrType.isMAC() {
		return MACBitsPerSegment
	}

	if section.GetDivisionCount() == 0 {
		return 0
	}

	return section.getDivision(0).GetBitCount()
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this section.
// Segments in the same address section are equal length.
func (section *addressSectionInternal) GetBytesPerSegment() int {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BytesPerSegment
	} else if addrType.isIPv6() {
		return IPv6BytesPerSegment
	} else if addrType.isMAC() {
		return MACBytesPerSegment
	}

	if section.GetDivisionCount() == 0 {
		return 0
	}

	return section.getDivision(0).GetByteCount()
}

func (section *addressSectionInternal) toAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *addressSectionInternal) toIPAddressSection() *IPAddressSection {
	return section.toAddressSection().ToIP()
}

func (section *addressSectionInternal) toIPv4AddressSection() *IPv4AddressSection {
	return section.toAddressSection().ToIPv4()
}

func (section *addressSectionInternal) toIPv6AddressSection() *IPv6AddressSection {
	return section.toAddressSection().ToIPv6()
}

func (section *addressSectionInternal) toMACAddressSection() *MACAddressSection {
	return section.toAddressSection().ToMAC()
}

func (section *addressSectionInternal) toPrefixBlock() *AddressSection {
	prefixLength := section.getPrefixLen()
	if prefixLength == nil {
		return section.toAddressSection()
	}

	return section.toPrefixBlockLen(prefixLength.bitCount())
}

func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	prefLen = checkSubnet(section, prefLen)
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section.toAddressSection()
	}

	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.getPrefixLen()
	prefixMatches := existingPrefixLength != nil && existingPrefixLength.bitCount() == prefLen
	if prefixMatches {
		prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		if prefixedSegmentIndex >= segCount {
			return section.toAddressSection()
		}
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex).bitCount()
		seg := section.GetSegment(prefixedSegmentIndex)
		if seg.containsPrefixBlock(segPrefLength) {
			i := prefixedSegmentIndex + 1
			for ; i < segCount; i++ {
				seg = section.GetSegment(i)
				if !seg.IsFullRange() {
					break
				}
			}
			if i == segCount {
				return section.toAddressSection()
			}
		}
	}

	prefixedSegmentIndex := 0
	newSegs := createSegmentArray(segCount)
	if prefLen > 0 {
		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		section.copySubDivisions(0, prefixedSegmentIndex, newSegs)
	}

	for i := prefixedSegmentIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
		oldSeg := section.getDivision(i)
		newSegs[i] = oldSeg.toPrefixedNetworkDivision(segPrefLength)
	}

	return createSectionMultiple(newSegs, cacheBitCount(prefLen), section.getAddrType(), section.isMultiple() || prefLen < section.GetBitCount())
}

func (section *addressSectionInternal) initImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			minPref := segment.GetMinPrefixLenForBlock()
			if minPref > 0 {
				if minPref != bitsPerSegment || i != segCount-1 {
					section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
				}
				return
			}
		}
		section.prefixLength = cacheBitCount(0)
	}
}

func (section *addressSectionInternal) initMultAndImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isMultiple := false
		isBlock := true
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			if isBlock {
				minPref := segment.GetMinPrefixLenForBlock()
				if minPref > 0 {
					if minPref != bitsPerSegment || i != segCount-1 {
						section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
					}
					isBlock = false
					if isMultiple { // nothing left to do
						return
					}
				}
			}
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
				if !isBlock { // nothing left to do
					return
				}
			}
		}
		if isBlock {
			section.prefixLength = cacheBitCount(0)
		}
	}
}

func (section *addressSectionInternal) createLowestHighestSections() (lower, upper *AddressSection) {
	var highSegs []*AddressDivision
	segmentCount := section.GetSegmentCount()
	lowSegs := createSegmentArray(segmentCount)

	if section.isMultiple() {
		highSegs = createSegmentArray(segmentCount)
	}

	for i := 0; i < segmentCount; i++ {
		seg := section.GetSegment(i)
		lowSegs[i] = seg.GetLower().ToDiv()
		if highSegs != nil {
			highSegs[i] = seg.GetUpper().ToDiv()
		}
	}

	lower = deriveAddressSection(section.toAddressSection(), lowSegs)

	if highSegs == nil {
		upper = lower
	} else {
		upper = deriveAddressSection(section.toAddressSection(), highSegs)
	}

	return
}

func (section *addressSectionInternal) getLowestHighestSections() (lower, upper *AddressSection) {
	if !section.isMultiple() {
		lower = section.toAddressSection()
		upper = lower
		return
	}

	cache := section.cache
	if cache == nil {
		return section.createLowestHighestSections()
	}

	cached := (*groupingCache)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.sectionCache))))
	if cached == nil {
		cached = &groupingCache{}
		cached.lower, cached.upper = section.createLowestHighestSections()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.sectionCache))
		atomicStorePointer(dataLoc, unsafe.Pointer(cached))
	}

	lower = cached.lower
	upper = cached.upper

	return
}

func (section *addressSectionInternal) getLower() *AddressSection {
	lower, _ := section.getLowestHighestSections()
	return lower
}

func (section *addressSectionInternal) getUpper() *AddressSection {
	_, upper := section.getLowestHighestSections()
	return upper
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (section *addressSectionInternal) GetMaxSegmentValue() SegInt {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4MaxValuePerSegment
	} else if addrType.isIPv6() {
		return IPv6MaxValuePerSegment
	} else if addrType.isMAC() {
		return MACMaxValuePerSegment
	}

	divLen := section.GetDivisionCount()
	if divLen == 0 {
		return 0
	}
	return section.GetSegment(0).GetMaxValue()
}

func (section *addressSectionInternal) toBlock(segmentIndex int, lower, upper SegInt) *AddressSection {
	segCount := section.GetSegmentCount()
	i := segmentIndex
	if i < 0 {
		i = 0
	}

	maxSegVal := section.GetMaxSegmentValue()

	for ; i < segCount; i++ {
		seg := section.GetSegment(segmentIndex)
		var lowerVal, upperVal SegInt
		if i == segmentIndex {
			lowerVal, upperVal = lower, upper
		} else {
			upperVal = maxSegVal
		}
		if !segsSame(nil, seg.getDivisionPrefixLength(), lowerVal, seg.GetSegmentValue(), upperVal, seg.GetUpperSegmentValue()) {
			newSegs := createSegmentArray(segCount)
			section.copySubDivisions(0, i, newSegs)
			newSeg := createAddressDivision(seg.deriveNewMultiSeg(lowerVal, upperVal, nil))
			newSegs[i] = newSeg
			var allSeg *AddressDivision
			if j := i + 1; j < segCount {
				if i == segmentIndex {
					allSeg = createAddressDivision(seg.deriveNewMultiSeg(0, maxSegVal, nil))
				} else {
					allSeg = newSeg
				}
				newSegs[j] = allSeg
				for j++; j < segCount; j++ {
					newSegs[j] = allSeg
				}
			}
			return createSectionMultiple(newSegs, nil, section.getAddrType(),
				segmentIndex < segCount-1 || lower != upper)
		}
	}
	return section.toAddressSection()
}

func (section *addressSectionInternal) getAdjustedPrefix(adjustment BitCount) BitCount {
	var result BitCount
	bitCount := section.GetBitCount()
	prefix := section.getPrefixLen()
	if prefix == nil {
		if adjustment > 0 { // start from 0
			if adjustment > bitCount {
				result = bitCount
			} else {
				result = adjustment
			}
		} else { // start from end
			if -adjustment < bitCount {
				result = bitCount + adjustment
			}
		}
	} else {
		result = prefix.bitCount() + adjustment
		if result > bitCount {
			result = bitCount
		} else if result < 0 {
			result = 0
		}
	}
	return result
}

// getSubnetSegments called by methods to adjust/remove/set prefix length, masking methods, zero host and zero network methods
func (section *addressSectionInternal) getSubnetSegments(startIndex int, networkPrefixLength PrefixLen, verifyMask bool, segProducer func(int) *AddressDivision, segmentMaskProducer func(int) SegInt) (res *AddressSection, err address_error.IncompatibleAddressError) {
	networkPrefixLength = checkPrefLen(networkPrefixLength, section.GetBitCount())
	bitsPerSegment := section.GetBitsPerSegment()
	count := section.GetSegmentCount()
	for i := startIndex; i < count; i++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		seg := segProducer(i)
		//note that the mask can represent a range (for example a CIDR mask),
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		maskValue := segmentMaskProducer(i)
		origValue, origUpperValue := seg.getSegmentValue(), seg.getUpperSegmentValue()
		value, upperValue := origValue, origUpperValue
		if verifyMask {
			mask64 := uint64(maskValue)
			val64 := uint64(value)
			upperVal64 := uint64(upperValue)
			masker := MaskRange(val64, upperVal64, mask64, seg.GetMaxValue())
			if !masker.IsSequential() {
				err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
				return
			}
			value = SegInt(masker.GetMaskedLower(val64, mask64))
			upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
		} else {
			value &= maskValue
			upperValue &= maskValue
		}
		if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
			newSegments := createSegmentArray(count)
			section.copySubDivisions(0, i, newSegments)
			newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
			for i++; i < count; i++ {
				segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
				seg = segProducer(i)
				maskValue = segmentMaskProducer(i)
				origValue, origUpperValue = seg.getSegmentValue(), seg.getUpperSegmentValue()
				value, upperValue = origValue, origUpperValue
				if verifyMask {
					mask64 := uint64(maskValue)
					val64 := uint64(value)
					upperVal64 := uint64(upperValue)
					masker := MaskRange(val64, upperVal64, mask64, seg.GetMaxValue())
					if !masker.IsSequential() {
						err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
						return
					}
					value = SegInt(masker.GetMaskedLower(val64, mask64))
					upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
				} else {
					value &= maskValue
					upperValue &= maskValue
				}
				if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
					newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
				} else {
					newSegments[i] = seg
				}
			}
			res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegments, networkPrefixLength)
			return
		}
	}
	res = section.toAddressSection()
	return
}

func (section *addressSectionInternal) setPrefixLength(networkPrefixLength BitCount, withZeros bool) (res *AddressSection, err address_error.IncompatibleAddressError) {
	existingPrefixLength := section.getPrefixLen()
	if existingPrefixLength != nil && networkPrefixLength == existingPrefixLength.bitCount() {
		res = section.toAddressSection()
		return
	}

	var appliedPrefixLen PrefixLen // purposely nil when there are no segments
	var segmentMaskProducer func(int) SegInt
	var startIndex int
	verifyMask := false
	segmentCount := section.GetSegmentCount()
	if segmentCount != 0 {
		maxVal := section.GetMaxSegmentValue()
		appliedPrefixLen = cacheBitCount(networkPrefixLength)
		var minPrefIndex, maxPrefIndex int
		var minPrefLen, maxPrefLen BitCount
		bitsPerSegment := section.GetBitsPerSegment()
		bytesPerSegment := section.GetBytesPerSegment()
		prefIndex := getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
		if existingPrefixLength != nil {
			verifyMask = true
			existingPrefLen := existingPrefixLength.bitCount()
			existingPrefIndex := getNetworkSegmentIndex(existingPrefLen, bytesPerSegment, bitsPerSegment) // can be -1 if existingPrefLen is 0
			if prefIndex > existingPrefIndex {
				maxPrefIndex = prefIndex
				minPrefIndex = existingPrefIndex
			} else {
				maxPrefIndex = existingPrefIndex
				minPrefIndex = prefIndex
			}
			if withZeros {
				if networkPrefixLength < existingPrefLen {
					minPrefLen = networkPrefixLength
					maxPrefLen = existingPrefLen
				} else {
					minPrefLen = existingPrefLen
					maxPrefLen = networkPrefixLength
				}
				startIndex = minPrefIndex
				segmentMaskProducer = func(i int) SegInt {
					if i >= minPrefIndex {
						if i <= maxPrefIndex {
							minSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, minPrefLen, i).bitCount()
							minMask := maxVal << uint(bitsPerSegment-minSegPrefLen)
							maxSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, maxPrefLen, i)
							if maxSegPrefLen != nil {
								maxMask := maxVal << uint(bitsPerSegment-maxSegPrefLen.bitCount())
								return minMask | ^maxMask
							}
							return minMask
						}
					}
					return maxVal
				}
			} else {
				startIndex = minPrefIndex
			}
		} else {
			startIndex = prefIndex
		}
		if segmentMaskProducer == nil {
			segmentMaskProducer = func(i int) SegInt {
				return maxVal
			}
		}
	}

	if startIndex < 0 {
		startIndex = 0
	}

	return section.getSubnetSegments(
		startIndex,
		appliedPrefixLen,
		verifyMask,
		func(i int) *AddressDivision {
			return section.getDivision(i)
		},
		segmentMaskProducer,
	)
}

func (section *addressSectionInternal) setPrefixLen(prefixLen BitCount) *AddressSection {
	// no zeroing
	res, _ := section.setPrefixLength(prefixLen, false)
	return res
}

func (section *addressSectionInternal) adjustPrefixLength(adjustment BitCount, withZeros bool) (*AddressSection, address_error.IncompatibleAddressError) {
	if adjustment == 0 && section.isPrefixed() {
		return section.toAddressSection(), nil
	}

	prefix := section.getAdjustedPrefix(adjustment)
	return section.setPrefixLength(prefix, withZeros)
}

func (section *addressSectionInternal) adjustPrefixLen(adjustment BitCount) *AddressSection {
	// no zeroing
	res, _ := section.adjustPrefixLength(adjustment, false)
	return res
}

func (section *addressSectionInternal) adjustPrefixLenZeroed(adjustment BitCount) (*AddressSection, address_error.IncompatibleAddressError) {
	return section.adjustPrefixLength(adjustment, true)
}

func (section *addressSectionInternal) matchesTypeAndCount(other *AddressSection) (matches bool, count int) {
	count = section.GetDivisionCount()
	if count != other.GetDivisionCount() {
		return
	} else if section.getAddrType() != other.getAddrType() {
		return
	}
	matches = true
	return
}

func (section *addressSectionInternal) sameCountTypeEquals(other *AddressSection) bool {
	count := section.GetSegmentCount()
	for i := count - 1; i >= 0; i-- {
		if !section.GetSegment(i).sameTypeEquals(other.GetSegment(i)) {
			return false
		}
	}
	return true
}

func (section *addressSectionInternal) equal(otherT AddressSectionType) bool {
	if otherT == nil {
		return false
	}

	other := otherT.ToSectionBase()
	if other == nil {
		return false
	}

	matchesStructure, _ := section.matchesTypeAndCount(other)

	return matchesStructure && section.sameCountTypeEquals(other)
}

func (section *addressSectionInternal) sameCountTypeContains(other *AddressSection) bool {
	count := section.GetSegmentCount()
	for i := count - 1; i >= 0; i-- {
		if !section.GetSegment(i).sameTypeContains(other.GetSegment(i)) {
			return false
		}
	}
	return true
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0,
// calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (section *addressSectionInternal) ForEachSegment(consumer func(segmentIndex int, segment *AddressSegment) (stop bool)) int {
	divArray := section.getDivArray()
	if divArray != nil {
		for i, div := range divArray {
			if consumer(i, div.ToSegmentBase()) {
				return i + 1
			}
		}
	}
	return len(divArray)
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (section *addressSectionInternal) GetBitCount() BitCount {
	divLen := section.GetDivisionCount()
	if divLen == 0 {
		return 0
	}
	return getSegmentsBitCount(section.getDivision(0).GetBitCount(), section.GetSegmentCount())
}

// GetByteCount returns the number of bytes required for each value comprising this address item.
func (section *addressSectionInternal) GetByteCount() int {
	return int((section.GetBitCount() + 7) >> 3)
}

// IsOneBit returns true if the bit in the lower value of this section at the given index is 1,
// where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (section *addressSectionInternal) IsOneBit(prefixBitIndex BitCount) bool {
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	segment := section.GetSegment(getHostSegmentIndex(prefixBitIndex, bytesPerSegment, bitsPerSegment))
	segmentBitIndex := prefixBitIndex % bitsPerSegment
	return segment.IsOneBit(segmentBitIndex)
}

// Gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (section *addressSectionInternal) getSubSection(index, endIndex int) *AddressSection {
	if index < 0 {
		index = 0
	}

	thisSegmentCount := section.GetSegmentCount()
	if endIndex > thisSegmentCount {
		endIndex = thisSegmentCount
	}

	segmentCount := endIndex - index
	if segmentCount <= 0 {
		if thisSegmentCount == 0 {
			return section.toAddressSection()
		}
		// we do not want an inconsistency where mac zero length can have prefix len zero while ip sections cannot
		return zeroSection
	}

	if index == 0 && endIndex == thisSegmentCount {
		return section.toAddressSection()
	}

	segs := section.getSubDivisions(index, endIndex)
	newPrefLen := section.getPrefixLen()
	if newPrefLen != nil {
		newPrefLen = getAdjustedPrefixLength(section.GetBitsPerSegment(), newPrefLen.bitCount(), index, endIndex)
	}

	addrType := section.getAddrType()

	if !section.isMultiple() {
		return createSection(segs, newPrefLen, addrType)
	}

	return deriveAddressSectionPrefLen(section.toAddressSection(), segs, newPrefLen)
}

// TestBit returns true if the bit in the lower value of this section at the given index is 1, where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this section.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (section *addressSectionInternal) TestBit(n BitCount) bool {
	return section.IsOneBit(section.GetBitCount() - (n + 1))
}

func (section *addressSectionInternal) withoutPrefixLen() *AddressSection {
	if !section.isPrefixed() {
		return section.toAddressSection()
	}

	if sect := section.toIPAddressSection(); sect != nil {
		return sect.withoutPrefixLen().ToSectionBase()
	}

	return createSectionMultiple(section.getDivisionsInternal(), nil, section.getAddrType(), section.isMultiple())
}

func (section *addressSectionInternal) toAboveOrBelow(above bool) *AddressSection {
	prefLen := section.GetPrefixLen()
	if prefLen == nil {
		return section.toAddressSection()
	}

	segmentCount := section.GetSegmentCount()
	prefBits := prefLen.Len()
	if prefBits == section.GetBitCount() || segmentCount == 0 {
		return section.withoutPrefixLen()
	}

	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	newSegs := createSegmentArray(segmentCount)

	if prefBits > 0 {
		networkSegmentIndex := getNetworkSegmentIndex(prefBits, segmentByteCount, segmentBitCount)
		section.copySubDivisions(0, networkSegmentIndex, newSegs)
	}

	hostSegmentIndex := getHostSegmentIndex(prefBits, segmentByteCount, segmentBitCount)
	if hostSegmentIndex < segmentCount {
		var newVal SegInt
		oldSeg := section.getDivision(hostSegmentIndex)
		oldVal := oldSeg.getUpperSegmentValue()
		segPrefBits := getPrefixedSegmentPrefixLength(segmentBitCount, prefBits, hostSegmentIndex).bitCount()
		// 1 bit followed by zeros
		allOnes := ^SegInt(0)

		if above {
			hostBits := uint(segmentBitCount - segPrefBits)
			networkMask := allOnes << (hostBits - 1)
			hostMask := ^(allOnes << hostBits)
			newVal = (oldVal | hostMask) & networkMask
		} else {
			hostBits := uint(segmentBitCount - segPrefBits)
			networkMask := allOnes << hostBits
			hostMask := ^(allOnes<<hostBits - 1)
			newVal = (oldVal & networkMask) | hostMask
		}

		newSegs[hostSegmentIndex] = createAddressDivision(oldSeg.deriveNewSeg(newVal, nil))

		if j := hostSegmentIndex + 1; j < segmentCount {
			var endSeg *AddressDivision
			if above {
				endSeg = createAddressDivision(oldSeg.deriveNewSeg(0, nil))
			} else {
				maxSegVal := section.GetMaxSegmentValue()
				endSeg = createAddressDivision(oldSeg.deriveNewSeg(maxSegVal, nil))
			}
			newSegs[j] = endSeg
			for j++; j < segmentCount; j++ {
				newSegs[j] = endSeg
			}
		}
	}
	return deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
}

// Returns the address created by converting this address to
// an address with a 0 as the first bit following the prefix,
// followed by all ones to the end, and with the prefix length then removed
// Returns the same address if it has no prefix length.
func (section *addressSectionInternal) toMaxLower() *AddressSection {
	return section.toAboveOrBelow(false)
}

// Returns the address created by converting this address to
// an address with a 1 as the first bit following the prefix,
// followed by all zeros to the end, and with the prefix length then removed
// Returns the same address if it has no prefix length
func (section *addressSectionInternal) toMinUpper() *AddressSection {
	return section.toAboveOrBelow(true)
}

func (section *addressSectionInternal) reverseSegments(segProducer func(int) (*AddressSegment, address_error.IncompatibleAddressError)) (res *AddressSection, err address_error.IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if count == 0 { // case count == 1 we cannot exit early, we need to apply segProducer to each segment
		return section.withoutPrefixLen(), nil
	}

	newSegs := createSegmentArray(count)
	isSame := !section.isPrefixed() //when reversing, the prefix must go
	halfCount := count >> 1
	i := 0
	for j := count - 1; i < halfCount; i, j = i+1, j-1 {
		var newj, newi *AddressSegment
		if newj, err = segProducer(i); err != nil {
			return
		}
		if newi, err = segProducer(j); err != nil {
			return
		}
		origi := section.GetSegment(i)
		origj := section.GetSegment(j)
		newSegs[j] = newj.ToDiv()
		newSegs[i] = newi.ToDiv()
		if isSame &&
			!(segValsSame(newi.getSegmentValue(), origi.getSegmentValue(), newi.getUpperSegmentValue(), origi.getUpperSegmentValue()) &&
				segValsSame(newj.getSegmentValue(), origj.getSegmentValue(), newj.getUpperSegmentValue(), origj.getUpperSegmentValue())) {
			isSame = false
		}
	}

	if (count & 1) == 1 { //the count is odd, handle the middle one
		seg := section.getDivision(i)
		newSegs[i] = seg // gets segment i without prefix length
	}

	if isSame {
		res = section.toAddressSection()
		return
	}

	res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)

	return
}

// callers to replace have ensures the component sections have consistent prefix lengths for the replacement
func (section *addressSectionInternal) replace(index, endIndex int, replacement *AddressSection, replacementStartIndex, replacementEndIndex int, prefixLen PrefixLen) *AddressSection {
	otherSegmentCount := replacementEndIndex - replacementStartIndex
	segmentCount := section.GetSegmentCount()
	totalSegmentCount := segmentCount + otherSegmentCount - (endIndex - index)
	segs := createSegmentArray(totalSegmentCount)
	sect := section.toAddressSection()
	sect.copySubDivisions(0, index, segs)

	if index < totalSegmentCount {
		replacement.copySubDivisions(replacementStartIndex, replacementEndIndex, segs[index:])
		if index+otherSegmentCount < totalSegmentCount {
			sect.copySubDivisions(endIndex, segmentCount, segs[index+otherSegmentCount:])
		}
	}

	addrType := sect.getAddrType()
	if addrType.isZeroSegments() { // zero-length section
		addrType = replacement.getAddrType()
	}

	return createInitializedSection(segs, prefixLen, addrType)
}

func (section *addressSectionInternal) setPrefixLenZeroed(prefixLen BitCount) (*AddressSection, address_error.IncompatibleAddressError) {
	return section.setPrefixLength(prefixLen, true)
}

// replaceLen replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
// ending before replacementEndIndex from the replacement section.
func (section *addressSectionInternal) replaceLen(startIndex, endIndex int, replacement *AddressSection, replacementStartIndex, replacementEndIndex int, segmentToBitsShift uint) *AddressSection {
	segmentCount := section.GetSegmentCount()
	startIndex, endIndex, replacementStartIndex, replacementEndIndex =
		adjustIndices(startIndex, endIndex, segmentCount, replacementStartIndex, replacementEndIndex, replacement.GetSegmentCount())

	replacedCount := endIndex - startIndex
	replacementCount := replacementEndIndex - replacementStartIndex

	// unlike ipvx, sections of zero length with 0 prefix are still considered to be applying their prefix during replacement,
	// because you can have zero length prefixes when there are no bits in the section
	prefixLength := section.getPrefixLen()
	if replacementCount == 0 && replacedCount == 0 {
		if prefixLength != nil {
			prefLen := prefixLength.bitCount()
			if prefLen <= BitCount(startIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			} else {
				replacementPrefisLength := replacement.getPrefixLen()
				if replacementPrefisLength == nil {
					return section.toAddressSection()
				} else if replacementPrefisLength.bitCount() > BitCount(replacementStartIndex<<segmentToBitsShift) {
					return section.toAddressSection()
				}
			}
		} else {
			replacementPrefisLength := replacement.getPrefixLen()
			if replacementPrefisLength == nil {
				return section.toAddressSection()
			} else if replacementPrefisLength.bitCount() > BitCount(replacementStartIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			}
		}
	} else if segmentCount == replacedCount {
		if prefixLength == nil || prefixLength.bitCount() > 0 {
			return replacement
		} else {
			replacementPrefisLength := replacement.getPrefixLen()
			if replacementPrefisLength != nil && replacementPrefisLength.bitCount() == 0 { // prefix length is 0
				return replacement
			}
		}
	}

	startBits := BitCount(startIndex << segmentToBitsShift)
	var newPrefixLength PrefixLen
	if prefixLength != nil && prefixLength.bitCount() <= startBits {
		newPrefixLength = prefixLength
	} else {
		replacementPrefLen := replacement.getPrefixLen()
		if replacementPrefLen != nil && replacementPrefLen.bitCount() <= BitCount(replacementEndIndex<<segmentToBitsShift) {
			var replacementPrefixLen BitCount
			replacementStartBits := BitCount(replacementStartIndex << segmentToBitsShift)
			if replacementPrefLen.bitCount() > replacementStartBits {
				replacementPrefixLen = replacementPrefLen.bitCount() - replacementStartBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementPrefixLen)
		} else if prefixLength != nil {
			replacementBits := BitCount(replacementCount << segmentToBitsShift)
			var endPrefixBits BitCount
			endIndexBits := BitCount(endIndex << segmentToBitsShift)
			if prefixLength.bitCount() > endIndexBits {
				endPrefixBits = prefixLength.bitCount() - endIndexBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementBits + endPrefixBits)
		} else {
			newPrefixLength = nil
		}
	}

	return section.replace(startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, newPrefixLength)
}

// Constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
// such that the range of values are a set of subnet blocks for that prefix.
func (section *addressSectionInternal) assignMinPrefixForBlock() *AddressSection {
	return section.setPrefixLen(section.GetMinPrefixLenForBlock())
}

func (section *addressSectionInternal) contains(other AddressSectionType) bool {
	if other == nil {
		return true
	}

	otherSection := other.ToSectionBase()
	if section.toAddressSection() == otherSection || otherSection == nil {
		return true
	}

	//check if they are comparable first
	matches, count := section.matchesTypeAndCount(otherSection)
	if !matches {
		return false
	} else {
		for i := count - 1; i >= 0; i-- {
			if !section.GetSegment(i).sameTypeContains(otherSection.GetSegment(i)) {
				return false
			}
		}
	}

	return true
}

func (section *addressSectionInternal) getStringCache() *stringCache {
	if section.hasNoDivisions() {
		return &zeroStringCache
	}

	cache := section.cache
	if cache == nil {
		return nil
	}

	return &cache.stringCache
}

func (section addressSectionInternal) writeStrFmt(state fmt.State, verb rune, str string, zone Zone) {
	var leftPaddingCount, rightPaddingCount int

	if precision, hasPrecision := state.Precision(); hasPrecision && len(str) > precision {
		str = str[:precision]
	}

	if verb == 'q' {
		if state.Flag('#') && (zone == NoZone || strconv.CanBackquote(string(zone))) {
			str = "`" + str + "`"
		} else if zone == NoZone {
			str = `"` + str + `"`
		} else {
			str = strconv.Quote(str) // zones should not have special characters, but you cannot be sure
		}
	}

	if width, hasWidth := state.Width(); hasWidth && len(str) < width { // padding required
		paddingCount := width - len(str)
		if state.Flag('-') {
			// right padding with spaces (takes precedence over '0' flag)
			rightPaddingCount = paddingCount
		} else {
			// left padding with spaces
			leftPaddingCount = paddingCount
		}
	}

	// left padding/str/right padding
	writeBytes(state, ' ', leftPaddingCount)
	_, _ = state.Write([]byte(str))
	writeBytes(state, ' ', rightPaddingCount)
}

func (section addressSectionInternal) writeNumberFmt(state fmt.State, verb rune, str string, zone Zone) {
	var prefix, address_String, secondStr string
	var separator byte

	if verb == 'O' {
		prefix = otherOctalPrefix // "0o"
	} else if state.Flag('#') {
		switch verb {
		case 'x':
			prefix = HexPrefix
		case 'X':
			prefix = otherHexPrefix
		case 'b':
			prefix = BinaryPrefix
		case 'o':
			prefix = OctalPrefix
		}
	}

	isMulti := section.isMultiple()
	if isMulti {
		separatorIndex := len(str) >> 1
		address_String = str[:separatorIndex]
		separator = str[separatorIndex]
		secondStr = str[separatorIndex+1:]
	} else {
		address_String = str
	}

	precision, hasPrecision := state.Precision()
	width, hasWidth := state.Width()
	usePrecision := hasPrecision

	if section.hasNoDivisions() {
		usePrecision = false
		prefix = ""
	}

	for {
		var zeroCount, leftPaddingCount, rightPaddingCount int
		if usePrecision {
			if len(address_String) > precision {
				frontChar := address_String[0]
				if frontChar == '0' {
					i := 1
					// eliminate leading zeros to match the precision (all the way to nothing)
					for len(address_String) > precision+i {
						frontChar = address_String[i]
						if frontChar != '0' {
							break
						}
						i++
					}
					address_String = address_String[i:]
				}
			} else if len(address_String) < precision {
				// expand to match the precision
				zeroCount = precision - len(address_String)
			}
		}

		length := len(prefix) + zeroCount + len(address_String)
		zoneRequired := len(zone) > 0
		if zoneRequired {
			length += len(zone) + 1
		}

		if hasWidth && length < width { // padding required
			paddingCount := width - length
			if state.Flag('-') {
				// right padding with spaces (takes precedence over '0' flag)
				rightPaddingCount = paddingCount
			} else if state.Flag('0') && !hasPrecision {
				// left padding with zeros
				zeroCount = paddingCount
			} else {
				// left padding with spaces
				leftPaddingCount = paddingCount
			}
		}

		// left padding/prefix/zeros/str/right padding
		writeBytes(state, ' ', leftPaddingCount)
		writeStr(state, prefix, 1)
		writeBytes(state, '0', zeroCount)
		_, _ = state.Write([]byte(address_String))

		if zoneRequired {
			_, _ = state.Write([]byte{IPv6ZoneSeparator})
			_, _ = state.Write([]byte(zone))
		}

		writeBytes(state, ' ', rightPaddingCount)

		if !isMulti {
			break
		}

		address_String = secondStr
		isMulti = false
		_, _ = state.Write([]byte{separator})
	}
}

func (section *addressSectionInternal) isDualString() (bool, address_error.IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if section.isMultiple() {
		//at this point we know we will return true, but we determine now if we must return address_error.IncompatibleAddressError
		for i := 0; i < count; i++ {
			division := section.GetSegment(i)
			if division.isMultiple() {
				isLastFull := true
				for j := count - 1; j >= i; j-- {
					division = section.GetSegment(j)
					if division.isMultiple() {
						if !isLastFull {
							return false, &incompatibleAddressError{addressError{key: "ipaddress.error.segmentMismatch"}}
						}
						isLastFull = division.IsFullRange()
					} else {
						isLastFull = false
					}
				}
				return true, nil
			}
		}
	}
	return false, nil
}

// used by iterator() and nonZeroHostIterator() in section types
func (section *addressSectionInternal) sectionIterator(excludeFunc func([]*AddressDivision) bool) Iterator[*AddressSection] {
	var original = section.toAddressSection()
	var iterator Iterator[[]*AddressDivision]
	useOriginal := !section.isMultiple()
	if useOriginal {
		if excludeFunc != nil && excludeFunc(section.getDivisionsInternal()) {
			original = nil // the single-valued iterator starts out empty
		}
	} else {
		iterator = allSegmentsIterator(
			section.GetSegmentCount(),
			nil,
			func(index int) Iterator[*AddressSegment] { return section.GetSegment(index).iterator() },
			excludeFunc)
	}
	return sectIterator(useOriginal, original, false, iterator)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this section includes the block of all values for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this section represents a single value, this returns the bit count.
func (section *addressSectionInternal) GetMinPrefixLenForBlock() BitCount {
	return section.addressDivisionGroupingInternal.GetMinPrefixLenForBlock()
}

// GetSequentialBlockCount provides the count of elements from the sequential block iterator,
// the minimal number of sequential address sections that comprise this address section.
func (section *addressSectionInternal) GetSequentialBlockCount() *big.Int {
	sequentialSegCount := section.GetSequentialBlockIndex()
	return section.GetPrefixCountLen(BitCount(sequentialSegCount) * section.GetBitsPerSegment())
}

func (section *addressSectionInternal) isMultipleTo(segmentCount int) bool {
	for i := 0; i < segmentCount; i++ {
		if section.GetSegment(i).isMultiple() {
			return true
		}
	}
	return false
}

func (section *addressSectionInternal) isMultipleFrom(segmentCount int) bool {
	segTotal := section.GetSegmentCount()
	for i := segmentCount; i < segTotal; i++ {
		if section.GetSegment(i).isMultiple() {
			return true
		}
	}
	return false
}

// IsZero returns whether this section matches exactly the value of zero.
func (section *addressSectionInternal) IsZero() bool {
	return section.addressDivisionGroupingInternal.IsZero()
}

// IncludesZero returns whether this section includes the value of zero within its range.
func (section *addressSectionInternal) IncludesZero() bool {
	return section.addressDivisionGroupingInternal.IncludesZero()
}

// IsMax returns whether this section matches exactly the maximum possible value,
// the value whose bits are all ones.
func (section *addressSectionInternal) IsMax() bool {
	return section.addressDivisionGroupingInternal.IsMax()
}

// IncludesMax returns whether this section includes the max value,
// the value whose bits are all ones, within its range.
func (section *addressSectionInternal) IncludesMax() bool {
	return section.addressDivisionGroupingInternal.IncludesMax()
}

// IsFullRange returns whether this address item represents all possible values attainable by an address item of this type.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (section *addressSectionInternal) IsFullRange() bool {
	return section.addressDivisionGroupingInternal.IsFullRange()
}

// GetSequentialBlockIndex gets the minimal segment index for which all following segments are full-range blocks.
//
// The segment at this index is not a full-range block itself, unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full address section to be sequential, the preceding segments must be single-valued.
func (section *addressSectionInternal) GetSequentialBlockIndex() int {
	return section.addressDivisionGroupingInternal.GetSequentialBlockIndex()
}

// GetPrefixLen returns the prefix length, or nil if there is no prefix length.
//
// A prefix length indicates the number of bits in the initial part of the address item that comprises the prefix.
//
// A prefix is a part of the address item that is not specific to that address but common amongst a group of such items,
// such as a CIDR prefix block subnet.
func (section *addressSectionInternal) GetPrefixLen() PrefixLen {
	return section.addressDivisionGroupingInternal.GetPrefixLen()
}

// GetValue returns the lowest individual address section in this address section as an integer value.
func (section *addressSectionInternal) GetValue() *big.Int {
	return section.addressDivisionGroupingInternal.GetValue()
}

// GetUpperValue returns the highest individual address section in this address section as an integer value.
func (section *addressSectionInternal) GetUpperValue() *big.Int {
	return section.addressDivisionGroupingInternal.GetUpperValue()
}

// ContainsPrefixBlock returns whether the values of this item contains the block of values for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (section *addressSectionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkSubnet(section, prefixLen)
	divCount := section.GetSegmentCount()
	bitsPerSegment := section.GetBitsPerSegment()
	i := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), bitsPerSegment)
	if i < divCount {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLen, i)
		if !div.ContainsPrefixBlock(segmentPrefixLength.bitCount()) {
			return false
		}
		for i++; i < divCount; i++ {
			div = section.GetSegment(i)
			if !div.IsFullRange() {
				return false
			}
		}
	}
	return true
}

// IsPrefixBlock returns whether this address segment series has a prefix length and includes the block associated with its prefix length.
// If the prefix length matches the bit count, this returns true.
//
// This is different from ContainsPrefixBlock in that this method returns
// false if the series has no prefix length or a prefix length that differs from a prefix length for which ContainsPrefixBlock returns true.
func (section *addressSectionInternal) IsPrefixBlock() bool {
	prefLen := section.getPrefixLen()
	return prefLen != nil && section.ContainsPrefixBlock(prefLen.bitCount())
}

// AddressSection is an address section containing a certain number of consecutive segments.
// It is a series of individual address segments.
// Each segment has the same bit length.
// Each address is backed by an address section that contains all address segments.
//
// AddressSection instances are immutable.
// This also makes them concurrency-safe.
//
// Most operations that can be performed on Address instances can also be performed on AddressSection instances, and vice versa.
type AddressSection struct {
	addressSectionInternal
}

// IsMultiple returns whether this section represents multiple values.
func (section *AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

// ToDivGrouping converts to AddressDivisionGrouping, a polymorphic type used with all address sections and divisional groupings.
// The conversion can then be reversed using ToSectionBase.
// ToDivGrouping can be called with a nil receiver, allowing this method to be used in a chain with methods that can return a nil pointer.
func (section *AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
}

// ToSectionBase is an identity method.
// ToSectionBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToSectionBase() *AddressSection {
	return section
}

// IsIPv4 returns true if this address section originated as an IPv4 section.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (section *AddressSection) IsIPv4() bool {
	return section != nil && section.matchesIPv4SectionType()
}

// IsIPv6 returns true if this address section originated as an IPv6 section.
// If so, use ToIPv6 to convert back to the IPv6-specific type.
func (section *AddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6SectionType()
}

// IsMAC returns true if this address section originated as a MAC section.
// If so, use ToMAC to convert back to the MAC-specific type.
func (section *AddressSection) IsMAC() bool {
	return section != nil && section.matchesMACSectionType()
}

// IsIP returns true if this address section originated as an IPv4 or IPv6 section, or a zero-length IP section.
// If so, use ToIP to convert back to the IP-specific type.
func (section *AddressSection) IsIP() bool {
	return section != nil && section.matchesIPSectionType()
}

// ToIP converts to an IPAddressSection if this address section originated as an IPv4 or IPv6 section,
// or an implicitly zero-valued IP section.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIP() *IPAddressSection {
	if section.IsIP() {
		return (*IPAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToIPv4 converts to an IPv4AddressSection if this section originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIPv4() *IPv4AddressSection {
	if section.IsIPv4() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToIPv6 converts to an IPv6AddressSection if this section originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToIPv6() *IPv6AddressSection {
	if section.IsIPv6() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

// ToMAC converts to a MACAddressSection if this section originated as a MAC section.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (section *AddressSection) ToMAC() *MACAddressSection {
	if section.IsMAC() {
		return (*MACAddressSection)(section)
	}
	return nil
}

// IsAdaptiveZero returns true if the division grouping was originally created as an implicitly zero-valued section or grouping (e.g. IPv4AddressSection{}),
// meaning it was not constructed using a constructor function.
// Such a grouping, which has no divisions or segments, is convertible to an implicitly zero-valued grouping of any type or version, whether IPv6, IPv4, MAC, or other.
// In other words, when a section or grouping is the zero-value, then it is equivalent and convertible to the zero value of any other section or grouping type.
func (section *AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

// ToPrefixBlock returns the section with the same prefix as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
//
// If this section has no prefix, this section is returned.
func (section *AddressSection) ToPrefixBlock() *AddressSection {
	return section.toPrefixBlock()
}

// ToPrefixBlockLen returns the section with the same prefix of the given length as this section while the remaining bits span all values.
// The returned section will be the block of all sections with the same prefix.
func (section *AddressSection) ToPrefixBlockLen(prefLen BitCount) *AddressSection {
	return section.toPrefixBlockLen(prefLen)
}

// GetLower returns the section in the range with the lowest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.2.4.5" is returned.
func (section *AddressSection) GetLower() *AddressSection {
	return section.getLower()
}

// GetUpper returns the section in the range with the highest numeric value,
// which will be the same section if it represents a single value.
// For example, for "1.2-3.4.5-6", the section "1.3.4.6" is returned.
func (section *AddressSection) GetUpper() *AddressSection {
	return section.getUpper()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address section.
//
// If this address section has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (section *AddressSection) AdjustPrefixLen(prefixLen BitCount) *AddressSection {
	return section.adjustPrefixLen(prefixLen).ToSectionBase()
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
func (section *AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*AddressSection, address_error.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToSectionBase(), err
}

func assignStringCache(section *addressDivisionGroupingBase, addrType addrType) {
	stringCache := &section.cache.stringCache
	if addrType.isIPv4() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv4StringCache = &ipv4StringCache{}
	} else if addrType.isIPv6() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv6StringCache = &ipv6StringCache{}
	} else if addrType.isMAC() {
		stringCache.macStringCache = &macStringCache{}
	}
}

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressSection {
	sect := &AddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions:    standardDivArray(segments),
					prefixLength: prefixLength,
					addrType:     addrType,
					cache:        &valueCache{},
				},
			},
		},
	}
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

func createDivisionsFromSegs(
	segProvider func(index int) *IPAddressSegment,
	segCount int,
	bitsToSegmentShift uint,
	bitsPerSegment BitCount,
	bytesPerSegment int,
	maxValuePerSegment SegInt,
	zeroSeg, zeroSegZeroPrefix, zeroSegPrefixBlock *IPAddressSegment,
	assignedPrefLen PrefixLen) (divs []*AddressDivision, newPref PrefixLen, isMultiple bool) {
	divs = make([]*AddressDivision, segCount)

	prefixedSegment := -1
	if assignedPrefLen != nil {
		p := assignedPrefLen.bitCount()
		if p < 0 {
			p = 0
			assignedPrefLen = cacheBitCount(p)
		} else {
			boundaryBits := BitCount(segCount << bitsToSegmentShift)
			if p > boundaryBits {
				p = boundaryBits
				assignedPrefLen = cacheBitCount(p)
			}
		}
		prefixedSegment = getNetworkSegmentIndex(p, bytesPerSegment, bitsPerSegment)
	}

	var previousSegPrefixed bool
	var lastSegment *IPAddressSegment
	for i := 0; i < segCount; i++ {
		segment := segProvider(i)
		if segment == nil {
			if previousSegPrefixed {
				divs[i] = zeroSegZeroPrefix.ToDiv()
			} else if i == prefixedSegment {
				newPref = cachePrefixLen(assignedPrefLen)
				segPref := getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), prefixedSegment)
				if i+1 < segCount && isPrefixSubnet(
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetSegmentValue()
					},
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetUpperSegmentValue()
					},
					segCount-(i+1), bytesPerSegment, bitsPerSegment, maxValuePerSegment, 0, zerosOnly) {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
					i++
					isMultiple = isMultiple || i < len(divs) || segPref.bitCount() < bitsPerSegment
					for ; i < len(divs); i++ {
						divs[i] = zeroSegPrefixBlock.ToDiv()
					}
					break
				} else {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
				}
			} else {
				divs[i] = zeroSeg.ToDiv() // nil segs are just zero
			}
		} else {
			// The final prefix length is the minimum amongst the assigned one and all of the segments' own prefixes
			segPrefix := segment.getDivisionPrefixLength()
			segIsPrefixed := segPrefix != nil
			if previousSegPrefixed {
				if !segIsPrefixed || segPrefix.bitCount() != 0 {
					divs[i] = createAddressDivision(
						segment.derivePrefixed(cacheBitCount(0))) // change seg prefix to 0
				} else {
					divs[i] = segment.ToDiv() // seg prefix is already 0
				}
			} else {
				// if a prefix length was supplied, we must check for prefix subnets
				var segPrefixSwitch bool
				var assignedSegPref PrefixLen
				if i == prefixedSegment || (prefixedSegment > 0 && segIsPrefixed) {
					// there exists an assigned prefix length
					assignedSegPref = getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), i)
					if segIsPrefixed {
						if assignedSegPref == nil || segPrefix.bitCount() < assignedSegPref.bitCount() {
							if segPrefix.bitCount() == 0 && i > 0 {
								// normalize boundaries by looking back
								if !lastSegment.IsPrefixed() {
									divs[i-1] = createAddressDivision(
										lastSegment.derivePrefixed(cacheBitCount(bitsPerSegment)))
								}
							}
							newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
						} else {
							newPref = cachePrefixLen(assignedPrefLen)
							segPrefixSwitch = assignedSegPref.bitCount() < segPrefix.bitCount()
						}
					} else {
						newPref = cachePrefixLen(assignedPrefLen)
						segPrefixSwitch = true
					}
					if isPrefixSubnet(
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetSegmentValue()
						},
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetUpperSegmentValue()
						},
						segCount,
						bytesPerSegment,
						bitsPerSegment,
						maxValuePerSegment,
						newPref.bitCount(),
						zerosOnly) {

						divs[i] = segment.toPrefixedNetworkDivision(assignedSegPref)
						i++
						isMultiple = isMultiple || i < len(divs) || newPref.bitCount() < bitsPerSegment
						for ; i < len(divs); i++ {
							divs[i] = zeroSegPrefixBlock.ToDiv()
						}
						break
					}
					previousSegPrefixed = true
				} else if segIsPrefixed {
					if segPrefix.bitCount() == 0 && i > 0 {
						// normalize boundaries by looking back
						if !lastSegment.IsPrefixed() {
							divs[i-1] = createAddressDivision(lastSegment.derivePrefixed(cacheBitCount(bitsPerSegment)))
						}
					}
					newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
					previousSegPrefixed = true
				}
				if segPrefixSwitch {
					divs[i] = createAddressDivision(segment.derivePrefixed(assignedSegPref)) // change seg prefix
				} else {
					divs[i] = segment.ToDiv()
				}
			}
			isMultiple = isMultiple || segment.isMultiple()
		}
		lastSegment = segment
	}
	return
}

// callers to this function supply segments with prefix length consistent with the supplied prefix length
func createSectionMultiple(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, isMultiple bool) *AddressSection {
	result := createSection(segments, prefixLength, addrType)
	result.isMult = isMultiple
	return result
}

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	assignedPrefixLength PrefixLen) (segments []*AddressDivision, err address_error.AddressValueError) {

	segments = createSegmentArray(segmentCount)
	byteIndex, segmentIndex := len(bytes), segmentCount-1
	for ; segmentIndex >= 0; segmentIndex-- {
		var value SegInt
		k := byteIndex - bytesPerSegment
		if k < 0 {
			k = 0
		}
		for j := k; j < byteIndex; j++ {
			byteValue := bytes[j]
			value <<= 8
			value |= SegInt(byteValue)
		}
		byteIndex = k
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, assignedPrefixLength, segmentIndex)
		seg := creator.createSegment(value, value, segmentPrefixLength)
		segments[segmentIndex] = seg
	}
	// any remaining bytes should be zero
	for byteIndex--; byteIndex >= 0; byteIndex-- {
		if bytes[byteIndex] != 0 {
			err = &addressValueError{
				addressError: addressError{key: "ipaddress.error.exceeds.size"},
				val:          int(bytes[byteIndex]),
			}
			break
		}
	}
	return
}

// callers to deriveAddressSection supply segments with prefix length consistent with the supplied prefix length
func deriveAddressSectionPrefLen(from *AddressSection, segments []*AddressDivision, prefixLength PrefixLen) *AddressSection {
	result := createSection(segments, prefixLength, from.getAddrType())
	result.initMultiple() // assigns isMultiple
	return result
}

// callers to deriveAddressSection supply segments with prefix length consistent with the prefix length of this section
func deriveAddressSection(from *AddressSection, segments []*AddressDivision) (res *AddressSection) {
	return deriveAddressSectionPrefLen(from, segments, from.prefixLength)
}

// callers to createInitializedSection supply segments with prefix length consistent with the supplied prefix length
func createInitializedSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressSection {
	result := createSection(segments, prefixLength, addrType)
	result.initMultiple() // assigns isMultiple
	return result
}

func seriesValsSame(one, two AddressSegmentSeries) bool {
	if one == two {
		return true
	}

	count := one.GetDivisionCount()
	if count != two.GetDivisionCount() {
		panic(two)
	}

	for i := count - 1; i >= 0; i-- { // reverse order since less significant segments more likely to differ
		oneSeg := one.GetGenericSegment(i)
		twoSeg := two.GetGenericSegment(i)
		if !segValsSame(oneSeg.GetSegmentValue(), twoSeg.GetSegmentValue(),
			oneSeg.GetUpperSegmentValue(), twoSeg.GetUpperSegmentValue()) {
			return false
		}
	}

	return true
}

func writeStr(state fmt.State, str string, count int) {
	if count > 0 && len(str) > 0 {
		bytes := []byte(str)
		for ; count > 0; count-- {
			_, _ = state.Write(bytes)
		}
	}
}

func writeBytes(state fmt.State, b byte, count int) {
	if count > 0 {
		bytes := make([]byte, count)
		for i := range bytes {
			bytes[i] = b
		}
		_, _ = state.Write(bytes)
	}
}
