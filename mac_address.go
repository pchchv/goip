package goip

import (
	"math/big"
	"net"

	"github.com/pchchv/goip/address_error"
)

const (
	MACBitsPerSegment                             = 8
	MACBytesPerSegment                            = 1
	MACDefaultTextualRadix                        = 16
	MACMaxValuePerSegment                         = 0xff
	MACMaxValuePerDottedSegment                   = 0xffff
	MediaAccessControlSegmentCount                = 6
	MediaAccessControlDottedSegmentCount          = 3
	MediaAccessControlDotted64SegmentCount        = 4
	ExtendedUniqueIdentifier48SegmentCount        = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount        = 8
	MACOrganizationalUniqueIdentifierSegmentCount = 3
	MACSegmentMaxChars                            = 2
	MACDashSegmentSeparator                       = '-'
	MACColonSegmentSeparator                      = ':'
	MacSpaceSegmentSeparator                      = ' '
	MacDottedSegmentSeparator                     = '.'
	MacDashedSegmentRangeSeparator                = '|'
	MacDashedSegmentRangeSeparatorStr             = "|"
	macBitsToSegmentBitshift                      = 3
)

var (
	zeroMAC             = createMACZero(false)
	macAll              = zeroMAC.SetPrefixLen(0).ToPrefixBlock()
	macAllExtended      = createMACZero(true).SetPrefixLen(0).ToPrefixBlock()
	IPv6LinkLocalPrefix = createLinkLocalPrefix()
)

// MACAddress represents a MAC address or a collection of multiple individual MAC addresses.
// Each segment may represent a single byte value or a range of byte values.
//
// A MAC address can be constructed from a byte slice, from a uint64, from a SegmentValueProvider,
// from a MACAddressSection of 6 or 8 segments, or from an array of 6 or 8 MACAddressSegment instances.
//
// To create a string from a string,
// use NewMACAddressString and then use the ToAddress or GetAddress method from [MACAddressString].
type MACAddress struct {
	addressInternal
}

// GetCount returns the count of addresses that this address or address collection represents.
//
// If just a single address, not a collection of multiple addresses, returns 1.
func (addr *MACAddress) init() *MACAddress {
	if addr.section == nil {
		return zeroMAC
	}
	return addr
}

// GetCount returns the count of addresses that this address or address collection represents.
//
// If just a single address, not a collection of multiple addresses, returns 1.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *MACAddress) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address, whether it is a collection of multiple addresses.
func (addr *MACAddress) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *MACAddress) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// GetBitsPerSegment returns the number of bits comprising each segment in this address.
// Segments in the same address are equal length.
func (addr *MACAddress) GetBitsPerSegment() BitCount {
	return MACBitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this address.
// Segments in the same address are equal length.
func (addr *MACAddress) GetBytesPerSegment() int {
	return MACBytesPerSegment
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToMAC.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *MACAddress) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(addr)
}

// GetDivisionCount returns the segment count, implementing the interface AddressDivisionSeries.
func (addr *MACAddress) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

// ToPrefixBlock returns the address associated with the prefix of this address or address collection,
// the address whose prefix matches the prefix of this address, and the remaining bits span all values.
// If this address has no prefix length, this address is returned.
//
// The returned address collection will include all addresses with the same prefix as this one, the prefix "block".
func (addr *MACAddress) ToPrefixBlock() *MACAddress {
	return addr.init().toPrefixBlock().ToMAC()
}

// ToPrefixBlockLen returns the address associated with the prefix length provided,
// the address collection whose prefix of that length matches the prefix of this address, and the remaining bits span all values.
//
// The returned address will include all addresses with the same prefix as this one, the prefix "block".
func (addr *MACAddress) ToPrefixBlockLen(prefLen BitCount) *MACAddress {
	return addr.init().toPrefixBlockLen(prefLen).ToMAC()
}

// ToBlock creates a new block of addresses by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr *MACAddress) ToBlock(segmentIndex int, lower, upper SegInt) *MACAddress {
	return addr.init().toBlock(segmentIndex, lower, upper).ToMAC()
}

// GetSection returns the backing section for this address or address collection, comprising all segments.
func (addr *MACAddress) GetSection() *MACAddressSection {
	return addr.init().section.ToMAC()
}

// GetBitCount returns the number of bits comprising this address,
// or each address in the range.
func (addr *MACAddress) GetBitCount() BitCount {
	return addr.init().addressInternal.GetBitCount()
}

// GetByteCount returns the number of bytes required for this address,
// or each address in the range.
func (addr *MACAddress) GetByteCount() int {
	return addr.init().addressInternal.GetByteCount()
}

// IsFullRange returns whether this address covers the entire MAC address space for its MAC bit length.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (addr *MACAddress) IsFullRange() bool {
	return addr.GetSection().IsFullRange()
}

func (addr *MACAddress) checkIdentity(section *MACAddressSection) *MACAddress {
	if section == nil {
		return nil
	}

	sec := section.ToSectionBase()
	if sec == addr.section {
		return addr
	}

	return newMACAddress(section)
}

// GetValue returns the lowest address in this subnet or address as an integer value.
func (addr *MACAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

// GetUpperValue returns the highest address in this subnet or address as an integer value.
func (addr *MACAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

// GetLower returns the address in the collection with the lowest numeric value,
// which will be the receiver if it represents a single address.
// For example, for "1:1:1:2-3:4:5-6", the series "1:1:1:2:4:5" is returned.
func (addr *MACAddress) GetLower() *MACAddress {
	return addr.init().getLower().ToMAC()
}

// GetUpper returns the address in the collection with the highest numeric value,
// which will be the receiver if it represents a single address.
// For example, for "1:1:1:2-3:4:5-6", the series "1:1:1:3:4:6" is returned.
func (addr *MACAddress) GetUpper() *MACAddress {
	return addr.init().getUpper().ToMAC()
}

// Bytes returns the lowest address in this address or address collection as a byte slice.
func (addr *MACAddress) Bytes() []byte {
	return addr.init().section.Bytes()
}

// UpperBytes returns the highest address in this address or address collection as a byte slice.
func (addr *MACAddress) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

// CopyUpperBytes copies the value of the highest individual address in the address collection into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *MACAddress) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

// GetHardwareAddr returns the lowest address in this address or address collection as a net.HardwareAddr.
func (addr *MACAddress) GetHardwareAddr() net.HardwareAddr {
	return addr.Bytes()
}

// CopyBytes copies the value of the lowest individual address in the address collection into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *MACAddress) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

// CopyHardwareAddr copies the value of the lowest individual address in the address collection into a net.HardwareAddr.
//
// If the value can fit in the given net.HardwareAddr,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new net.HardwareAddr is created and returned with the value.
func (addr *MACAddress) CopyHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyBytes(bytes)
}

// GetUpperHardwareAddr returns the highest address in this address or address collection as a net.HardwareAddr.
func (addr *MACAddress) GetUpperHardwareAddr() net.HardwareAddr {
	return addr.UpperBytes()
}

// CopyUpperHardwareAddr copies the value of the highest individual address in the address collection into a net.HardwareAddr.
//
// If the value can fit in the given net.HardwareAddr,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new net.HardwareAddr is created and returned with the value.
func (addr *MACAddress) CopyUpperHardwareAddr(bytes net.HardwareAddr) net.HardwareAddr {
	return addr.CopyUpperBytes(bytes)
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or
// an index matching or larger than the segment count.
func (addr *MACAddress) GetSegment(index int) *MACAddressSegment {
	return addr.init().getSegment(index).ToMAC()
}

// GetSegmentCount returns the segment/division count
func (addr *MACAddress) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// IsMax returns whether this address matches exactly the maximum possible value,
// the address whose bits are all ones.
func (addr *MACAddress) IsMax() bool {
	return addr.init().section.IsMax()
}

// IncludesMax returns whether this address includes the max address,
// the address whose bits are all ones, within its range.
func (addr *MACAddress) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (addr *MACAddress) SetPrefixLen(prefixLen BitCount) *MACAddress {
	return addr.init().setPrefixLen(prefixLen).ToMAC()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr *MACAddress) AdjustPrefixLen(prefixLen BitCount) *MACAddress {
	return addr.init().adjustPrefixLen(prefixLen).ToMAC()
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by
// the given increment while zeroing out the bits that have moved into or outside the prefix.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
//
// When prefix length is increased, the bits moved within the prefix become zero.
// When a prefix length is decreased, the bits moved outside the prefix become zero.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr *MACAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (*MACAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToMAC(), err
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (addr *MACAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

// IsMulticast returns whether this address or collection of addresses is entirely multicast.
// Multicast MAC addresses have the least significant bit of the first octet set to 1.
func (addr *MACAddress) IsMulticast() bool {
	return addr.GetSegment(0).MatchesWithMask(1, 0x1)
}

// IsUnicast returns whether this address or collection of addresses is entirely unicast.
// Unicast MAC addresses have the least significant bit of the first octet set to 0.
func (addr *MACAddress) IsUnicast() bool {
	return !addr.IsMulticast()
}

// IsUniversal returns whether this is a universal address.
// Universal MAC addresses have second the least significant bit of the first octet set to 0.
func (addr *MACAddress) IsUniversal() bool {
	return !addr.IsLocal()
}

// IsLocal returns whether this is a local address.
// Local MAC addresses have the second least significant bit of the first octet set to 1.
func (addr *MACAddress) IsLocal() bool {
	return addr.GetSegment(0).MatchesWithMask(2, 0x2)
}

// ToOUIPrefixBlock returns a section in which the range of values match the full block for the OUI (organizationally unique identifier) bytes
func (addr *MACAddress) ToOUIPrefixBlock() *MACAddress {
	segmentCount := addr.GetSegmentCount()
	currentPref := addr.getPrefixLen()
	newPref := BitCount(MACOrganizationalUniqueIdentifierSegmentCount) << 3 //ouiSegmentCount * MACAddress.BITS_PER_SEGMENT
	createNew := currentPref == nil || currentPref.bitCount() > newPref
	if !createNew {
		newPref = currentPref.bitCount()
		for i := MACOrganizationalUniqueIdentifierSegmentCount; i < segmentCount; i++ {
			segment := addr.GetSegment(i)
			if !segment.IsFullRange() {
				createNew = true
				break
			}
		}
	}

	if !createNew {
		return addr
	}

	segmentIndex := MACOrganizationalUniqueIdentifierSegmentCount
	newSegs := createSegmentArray(segmentCount)
	addr.GetSection().copySubDivisions(0, segmentIndex, newSegs)
	allRangeSegment := allRangeMACSeg.ToDiv()

	for i := segmentIndex; i < segmentCount; i++ {
		newSegs[i] = allRangeSegment
	}

	newSect := createSectionMultiple(newSegs, cacheBitCount(newPref), addr.getAddrType(), true).ToMAC()
	return newMACAddress(newSect)
}

// IsEUI64 returns whether this section is consistent with an IPv6 EUI64Size section,
// which means it came from an extended 8 byte address,
// and the corresponding segments in the middle match 0xff and 0xff/fe for MAC/not-MAC
func (addr *MACAddress) IsEUI64(asMAC bool) bool {
	if addr.GetSegmentCount() == ExtendedUniqueIdentifier64SegmentCount {
		section := addr.GetSection()
		seg3 := section.GetSegment(3)
		seg4 := section.GetSegment(4)
		if seg3.matches(0xff) {
			if asMAC {
				return seg4.matches(0xff)
			}
			return seg4.matches(0xfe)
		}
	}
	return false
}

// toAddressBase is needed for tries, it skips the init() call
func (addr *MACAddress) toAddressBase() *Address {
	return (*Address)(addr)
}

// Wrap wraps this address, returning a WrappedAddress, an implementation of ExtendedSegmentSeries,
// which can be used to write code that works with both addresses and address sections.
func (addr *MACAddress) Wrap() WrappedAddress {
	return wrapAddress(addr.ToAddressBase())
}

// Uint64Value returns the lowest address in the address collection as a uint64.
func (addr *MACAddress) Uint64Value() uint64 {
	return addr.GetSection().Uint64Value()
}

// UpperUint64Value returns the highest address in the address collection as a uint64.
func (addr *MACAddress) UpperUint64Value() uint64 {
	return addr.GetSection().UpperUint64Value()
}

// TestBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this address.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (addr *MACAddress) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// IsOneBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (addr *MACAddress) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

// WithoutPrefixLen provides the same address but with no prefix length.  The values remain unchanged.
func (addr *MACAddress) WithoutPrefixLen() *MACAddress {
	if !addr.IsPrefixed() {
		return addr
	}
	return addr.init().withoutPrefixLen().ToMAC()
}

// SetPrefixLenZeroed sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
//
// If this address has a prefix length, and the prefix length is increased when setting the new prefix length, the bits moved within the prefix become zero.
// If this address has a prefix length, and the prefix length is decreased when setting the new prefix length, the bits moved outside the prefix become zero.
//
// In other words, bits that move from one side of the prefix length to the other (bits moved into the prefix or outside the prefix) are zeroed.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr *MACAddress) SetPrefixLenZeroed(prefixLen BitCount) (*MACAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToMAC(), err
}

// AssignMinPrefixForBlock returns an equivalent subnet, assigned the smallest prefix length possible,
// such that the prefix block for that prefix length is in this subnet.
//
// In other words, this method assigns a prefix length to this subnet matching the largest prefix block in this subnet.
func (addr *MACAddress) AssignMinPrefixForBlock() *MACAddress {
	return addr.init().assignMinPrefixForBlock().ToMAC()
}

// ContainsPrefixBlock returns whether the range of this address or address collection contains the block of addresses for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (addr *MACAddress) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().addressInternal.ContainsPrefixBlock(prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this includes the block of addresses for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this represents just a single address, returns the bit length of this address.
func (addr *MACAddress) GetMinPrefixLenForBlock() BitCount {
	return addr.init().addressInternal.GetMinPrefixLenForBlock()
}

// Iterator provides an iterator to iterate through the individual addresses of this address or subnet.
//
// When iterating, the prefix length is preserved.
// Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual addresses.
//
// Call IsMultiple to determine if this instance represents multiple addresses, or GetCount for the count.
func (addr *MACAddress) Iterator() Iterator[*MACAddress] {
	if addr == nil {
		return macAddressIterator{nilAddrIterator()}
	}
	return macAddressIterator{addr.init().addrIterator(nil)}
}

// BlockIterator iterates through the addresses that can be obtained by iterating through all the upper segments up to the given segment count.
// The segments following remain the same in all iterated addresses.
func (addr *MACAddress) BlockIterator(segmentCount int) Iterator[*MACAddress] {
	return macAddressIterator{addr.init().blockIterator(segmentCount)}
}

// SequentialBlockIterator iterates through the sequential subnets or addresses that make up this address or subnet.
//
// Practically, this means finding the count of segments for which the segments that follow are not full range, and then using BlockIterator with that segment count.
//
// For instance, given the IPv4 subnet "1-2.3-4.5-6.7-8", it will iterate through "1.3.5.7-8", "1.3.6.7-8", "1.4.5.7-8", "1.4.6.7-8", "2.3.5.7-8", "2.3.6.7-8", "2.4.6.7-8" and "2.4.6.7-8".
//
// Use GetSequentialBlockCount to get the number of iterated elements.
func (addr *MACAddress) SequentialBlockIterator() Iterator[*MACAddress] {
	return macAddressIterator{addr.init().sequentialBlockIterator()}
}

// GetSequentialBlockIndex gets the minimal segment index for which all following segments are full-range blocks.
//
// The segment at this index is not a full-range block itself, unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full address collection to be sequential, the preceding segments must be single-valued.
func (addr *MACAddress) GetSequentialBlockIndex() int {
	return addr.init().getSequentialBlockIndex()
}

// GetSequentialBlockCount provides the count of elements from the sequential block iterator, the minimal number of sequential address ranges that comprise this address collection.
func (addr *MACAddress) GetSequentialBlockCount() *big.Int {
	return addr.init().getSequentialBlockCount()
}

// GetSegmentStrings returns a slice with the string for each segment being the string that is normalized with wildcards.
func (addr *MACAddress) GetSegmentStrings() []string {
	if addr == nil {
		return nil
	}
	return addr.init().getSegmentStrings()
}

// ToEUI64 converts to IPv6 EUI-64 section.
//
// If asMAC if true, this address is considered MAC and the EUI-64 is extended using ff-ff, otherwise this address is considered EUI-48 and extended using ff-fe
// Note that IPv6 treats MAC as EUI-48 and extends MAC to IPv6 addresses using ff-fe
func (addr *MACAddress) ToEUI64(asMAC bool) (*MACAddress, address_error.IncompatibleAddressError) {
	section := addr.GetSection()
	if addr.GetSegmentCount() == ExtendedUniqueIdentifier48SegmentCount {
		segs := createSegmentArray(ExtendedUniqueIdentifier64SegmentCount)
		section.copySubDivisions(0, 3, segs)
		segs[3] = ffMACSeg.ToDiv()
		if asMAC {
			segs[4] = ffMACSeg.ToDiv()
		} else {
			segs[4] = feMACSeg.ToDiv()
		}
		section.copySubDivisions(3, 6, segs[5:])
		prefixLen := addr.getPrefixLen()
		if prefixLen != nil {
			if prefixLen.bitCount() >= 24 {
				prefixLen = cacheBitCount(prefixLen.bitCount() + (MACBitsPerSegment << 1)) //two segments
			}
		}
		newSect := createInitializedSection(segs, prefixLen, addr.getAddrType()).ToMAC()
		return newMACAddress(newSect), nil
	}

	seg3 := section.GetSegment(3)
	seg4 := section.GetSegment(4)
	if seg3.matches(0xff) {
		if asMAC {
			if seg4.matches(0xff) {
				return addr, nil
			}
		} else {
			if seg4.matches(0xfe) {
				return addr, nil
			}
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
}

func (addr *MACAddress) toMaxLower() *MACAddress {
	return addr.init().addressInternal.toMaxLower().ToMAC()
}

func (addr *MACAddress) toMinUpper() *MACAddress {
	return addr.init().addressInternal.toMinUpper().ToMAC()
}

// GetSubSection gets the subsection from the series starting from
// the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (addr *MACAddress) GetSubSection(index, endIndex int) *MACAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (addr *MACAddress) GetTrailingSection(index int) *MACAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

// GetOUISection returns a section with the first 3 segments, the organizational unique identifier
func (addr *MACAddress) GetOUISection() *MACAddressSection {
	return addr.GetSubSection(0, MACOrganizationalUniqueIdentifierSegmentCount)
}

// GetODISection returns a section with the segments following the first 3 segments, the organizational distinct identifier
func (addr *MACAddress) GetODISection() *MACAddressSection {
	return addr.GetTrailingSection(MACOrganizationalUniqueIdentifierSegmentCount)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (addr *MACAddress) CopySubSegments(start, end int, segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (addr *MACAddress) CopySegments(segs []*MACAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this address.
func (addr *MACAddress) GetSegments() []*MACAddressSegment {
	return addr.GetSection().GetSegments()
}

// ForEachSegment visits each segment in order from most-significant to least,
// the most significant with index 0, calling the given function for each,
// terminating early if the function returns true.
// Returns the number of visited segments.
func (addr *MACAddress) ForEachSegment(consumer func(segmentIndex int, segment *MACAddressSegment) (stop bool)) int {
	return addr.GetSection().ForEachSegment(consumer)
}

// ReverseBytes returns a new address with the bytes reversed.
// Any prefix length is dropped.
func (addr *MACAddress) ReverseBytes() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseBytes())
}

// ReverseSegments returns a new address with the segments reversed.
func (addr *MACAddress) ReverseSegments() *MACAddress {
	return addr.checkIdentity(addr.GetSection().ReverseSegments())
}

// ReplaceLen replaces segments starting from startIndex and
// ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section.
// Mappings to or from indices outside the range of this or the replacement address are skipped.
func (addr *MACAddress) ReplaceLen(startIndex, endIndex int, replacement *MACAddress, replacementIndex int) *MACAddress {
	replacementSegCount := replacement.GetSegmentCount()
	if replacementIndex <= 0 {
		startIndex -= replacementIndex
		replacementIndex = 0
	} else if replacementIndex >= replacementSegCount {
		return addr
	}
	// We must do a 1 to 1 adjustment of indices before calling the section replace which would do an adjustment of indices not 1 to 1.
	// Here we assume replacementIndex is 0 and working on the subsection starting at that index.
	// In other words, a replacementIndex of x on the whole section is equivalent to replacementIndex of 0 on the shorter subsection starting at x.
	// Then afterwards we use the original replacement index to work on the whole section again, adjusting as needed.
	startIndex, endIndex, replacementIndexAdjustment := adjust1To1Indices(startIndex, endIndex, addr.GetSegmentCount(), replacementSegCount-replacementIndex)
	if startIndex == endIndex {
		return addr
	}
	replacementIndex += replacementIndexAdjustment
	count := endIndex - startIndex
	return addr.init().checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement.GetSection(), replacementIndex, replacementIndex+count))
}

// Replace replaces segments starting from startIndex with segments from the replacement section.
func (addr *MACAddress) Replace(startIndex int, replacement *MACAddressSection) *MACAddress {
	// We must do a 1 to 1 adjustment of indices before calling the section replace which would do an adjustment of indices not 1 to 1.
	startIndex, endIndex, replacementIndex :=
		adjust1To1Indices(startIndex, startIndex+replacement.GetSegmentCount(), addr.GetSegmentCount(), replacement.GetSegmentCount())
	count := endIndex - startIndex
	return addr.init().checkIdentity(addr.GetSection().ReplaceLen(startIndex, endIndex, replacement, replacementIndex, replacementIndex+count))
}

// ToLinkLocalIPv6 converts to a link-local Ipv6 address.
// Any MAC prefix length is ignored.
// Other elements of this address section are incorporated into the conversion.
// This will provide the latter 4 segments of an IPv6 address, to be paired with the link-local IPv6 prefix of 4 segments.
func (addr *MACAddress) ToLinkLocalIPv6() (*IPv6Address, address_error.IncompatibleAddressError) {
	sect, err := addr.ToEUI64IPv6()
	if err != nil {
		return nil, err
	}
	return newIPv6Address(IPv6LinkLocalPrefix.Append(sect)), nil
}

// ToEUI64IPv6 converts to an Ipv6 address section.  Any MAC prefix length is ignored.
// Other elements of this address section are incorporated into the conversion.
// This will provide the latter 4 segments of an IPv6 address, to be paired with an IPv6 prefix of 4 segments.
func (addr *MACAddress) ToEUI64IPv6() (*IPv6AddressSection, address_error.IncompatibleAddressError) {
	return NewIPv6SectionFromMAC(addr.init())
}

// GetDottedAddress returns an AddressDivisionGrouping which organizes the address into segments of bit-length 16,
// rather than the more typical 8 bits per segment.
//
// If this represents a collection of MAC addresses, this returns an error when unable to join two address segments,
// the first with a range of values, into a division of the larger bit-length that represents the same set of values.
func (addr *MACAddress) GetDottedAddress() (*AddressDivisionGrouping, address_error.IncompatibleAddressError) {
	return addr.init().GetSection().GetDottedGrouping()
}

func (addr *MACAddress) toSinglePrefixBlockOrAddress() (*MACAddress, address_error.IncompatibleAddressError) {
	if addr == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.address.not.block"}}
	}

	res := addr.ToSinglePrefixBlockOrAddress()
	if res == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.address.not.block"}}
	}

	return res, nil
}

// ToSinglePrefixBlockOrAddress converts to a single prefix block or address.
// If the given address is a single prefix block, it is returned.
// If it can be converted to a single prefix block by assigning a prefix length, the converted block is returned.
// If it is a single address, any prefix length is removed and the address is returned.
// Otherwise, nil is returned.
// This method provides the address formats used by tries.
// ToSinglePrefixBlockOrAddress is quite similar to AssignPrefixForSingleBlock,
// which always returns prefixed addresses, while this does not.
func (addr *MACAddress) ToSinglePrefixBlockOrAddress() *MACAddress {
	return addr.init().toSinglePrefixBlockOrAddr().ToMAC()
}

// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this address.
// The returned block will have an assigned prefix length indicating the prefix length for the block.
//
// There may be no such address - it is required that the range of values match the range of a prefix block.
// If there is no such address, then nil is returned.
func (addr *MACAddress) AssignPrefixForSingleBlock() *MACAddress {
	return addr.init().assignPrefixForSingleBlock().ToMAC()
}

// GetPrefixLenForSingleBlock returns a prefix length for which the range of
// this address collection matches the block of addresses for that prefix.
//
// If the range can be described this way, then this method returns the same value as GetMinPrefixLenForBlock.
//
// If no such prefix exists, returns nil.
//
// If this segment grouping represents a single value, this returns the bit length of this address.
func (addr *MACAddress) GetPrefixLenForSingleBlock() PrefixLen {
	return addr.init().addressInternal.GetPrefixLenForSingleBlock()
}

// ReverseBits returns a new address with the bits reversed.  Any prefix length is dropped.
//
// If the bits within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, this returns an error.
//
// In practice this means that to be reversible,
// a segment range must include all values except possibly the largest and/or smallest, which reverse to themselves.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (addr *MACAddress) ReverseBits(perByte bool) (*MACAddress, address_error.IncompatibleAddressError) {
	res, err := addr.GetSection().ReverseBits(perByte)
	if err != nil {
		return nil, err
	}
	return addr.checkIdentity(res), nil
}

// ToKey creates the associated address key.
// While addresses can be compared with the Compare or Equal methods as well as various provided instances of AddressComparator,
// they are not comparable with Go operators.
// However, AddressKey instances are comparable with Go operators, and thus can be used as map keys.
func (addr *MACAddress) ToKey() MACAddressKey {
	key := MACAddressKey{
		additionalByteCount: uint8(addr.GetSegmentCount()) - MediaAccessControlSegmentCount,
	}
	section := addr.GetSection()
	divs := section.getDivArray()
	var lowerVal, upperVal uint64
	if addr.IsMultiple() {
		for _, div := range divs {
			seg := div.ToMAC()
			lowerVal = (lowerVal << MACBitsPerSegment) | uint64(seg.GetMACSegmentValue())
			upperVal = (upperVal << MACBitsPerSegment) | uint64(seg.GetMACUpperSegmentValue())
		}
	} else {
		for _, div := range divs {
			seg := div.ToMAC()
			lowerVal = (lowerVal << MACBitsPerSegment) | uint64(seg.GetMACSegmentValue())
		}
		upperVal = lowerVal
	}
	key.vals.lower = lowerVal
	key.vals.upper = upperVal
	return key
}

func (addr *MACAddress) fromKey(scheme addressScheme, key *keyContents) *MACAddress {
	// See ToGenericKey for details such as the fact that the scheme is populated only for eui64Scheme
	return fromMACAddrKey(scheme, key)
}

func fromMACKey(key MACAddressKey) *MACAddress {
	additionalByteCount := key.additionalByteCount
	segCount := int(additionalByteCount) + MediaAccessControlSegmentCount
	return NewMACAddressFromRangeExt(
		func(segmentIndex int) MACSegInt {
			segIndex := (segCount - 1) - segmentIndex
			return MACSegInt(key.vals.lower >> (segIndex << macBitsToSegmentBitshift))
		}, func(segmentIndex int) MACSegInt {
			segIndex := (segCount - 1) - segmentIndex
			return MACSegInt(key.vals.upper >> (segIndex << macBitsToSegmentBitshift))
		},
		additionalByteCount != 0,
	)
}

func getMacSegCount(isExtended bool) (segmentCount int) {
	if isExtended {
		segmentCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		segmentCount = MediaAccessControlSegmentCount
	}
	return
}

func newMACAddress(section *MACAddressSection) *MACAddress {
	return createAddress(section.ToSectionBase(), NoZone).ToMAC()
}

func createMACZero(extended bool) *MACAddress {
	segs := []*MACAddressSegment{zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg, zeroMACSeg}
	if extended {
		segs = append(segs, zeroMACSeg, zeroMACSeg)
	}
	section := NewMACSection(segs)
	return newMACAddress(section)
}

func createLinkLocalPrefix() *IPv6AddressSection {
	zeroSeg := zeroIPv6Seg.ToDiv()
	segs := []*AddressDivision{
		NewIPv6Segment(0xfe80).ToDiv(),
		zeroSeg,
		zeroSeg,
		zeroSeg,
	}
	return newIPv6Section(segs)
}

// NewMACAddress constructs a MAC address or address collection from the given segments.
func NewMACAddress(section *MACAddressSection) (*MACAddress, address_error.AddressValueError) {
	segCount := section.GetSegmentCount()
	if segCount != MediaAccessControlSegmentCount && segCount != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

// NewMACAddressFromSegs constructs a MAC address or address collection from the given segments.
// If the given slice does not have either 6 or 8 segments, an error is returned.
func NewMACAddressFromSegs(segments []*MACAddressSegment) (*MACAddress, address_error.AddressValueError) {
	segsLen := len(segments)
	if segsLen != MediaAccessControlSegmentCount && segsLen != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{val: segsLen, addressError: addressError{key: "ipaddress.error.mac.invalid.segment.count"}}
	}

	section := NewMACSection(segments)
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

func createMACSectionFromBytes(bytes []byte) (*MACAddressSection, address_error.AddressValueError) {
	var segCount int
	length := len(bytes)
	// Round down the bytes to 6 bytes if we can.
	// Otherwise, we round up.
	if length < ExtendedUniqueIdentifier64SegmentCount {
		segCount = MediaAccessControlSegmentCount
		if length > MediaAccessControlSegmentCount {
			for i := 0; ; i++ {
				if bytes[i] != 0 {
					segCount = ExtendedUniqueIdentifier64SegmentCount
					break
				}
				length--
				if length <= MediaAccessControlSegmentCount {
					break
				}
			}
		}
	} else {
		segCount = ExtendedUniqueIdentifier64SegmentCount
	}
	return NewMACSectionFromBytes(bytes, segCount)
}

// NewMACAddressFromBytes constructs a MAC address from the given byte slice.
// An error is returned when the byte slice has too many bytes to match the maximum MAC segment count of 8.
// There should be 8 bytes or less, although extra leading zeros are tolerated.
func NewMACAddressFromBytes(bytes net.HardwareAddr) (*MACAddress, address_error.AddressValueError) {
	section, err := createMACSectionFromBytes(bytes)
	if err != nil {
		return nil, err
	}
	segCount := section.GetSegmentCount()
	if segCount != MediaAccessControlSegmentCount && segCount != ExtendedUniqueIdentifier64SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToMAC(), nil
}

// NewMACAddressFromUint64Ext constructs a 6 or 8-byte MAC address from the given value.
// If isExtended is true, it is an 8-byte address, 6 otherwise.
// If 6 bytes, then the bytes are taken from the lower 48 bits of the uint64.
func NewMACAddressFromUint64Ext(val uint64, isExtended bool) *MACAddress {
	section := NewMACSectionFromUint64(val, getMacSegCount(isExtended))
	return createAddress(section.ToSectionBase(), NoZone).ToMAC()
}

// NewMACAddressFromValsExt constructs a 6 or 8-byte MAC address from the given values.
// If isExtended is true, it will be 8 bytes.
func NewMACAddressFromValsExt(vals MACSegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromVals(vals, getMacSegCount(isExtended))
	addr = newMACAddress(section)
	return
}

// NewMACAddressFromRangeExt constructs a 6 or 8-byte MAC address collection from the given values.
// If isExtended is true, it will be 8 bytes.
func NewMACAddressFromRangeExt(vals, upperVals MACSegmentValueProvider, isExtended bool) (addr *MACAddress) {
	section := NewMACSectionFromRange(vals, upperVals, getMacSegCount(isExtended))
	addr = newMACAddress(section)
	return
}

// NewMACAddressFromVals constructs a 6-byte MAC address from the given values.
func NewMACAddressFromVals(vals MACSegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromValsExt(vals, false)
}

// NewMACAddressFromRange constructs a 6-byte MAC address collection from the given values.
func NewMACAddressFromRange(vals, upperVals MACSegmentValueProvider) (addr *MACAddress) {
	return NewMACAddressFromRangeExt(vals, upperVals, false)
}

func fromMACAddrKey(scheme addressScheme, key *keyContents) *MACAddress {
	segCount := MediaAccessControlSegmentCount
	isExtended := false
	// Note: the check here must be for eui64Scheme and not mac48Scheme
	// ToGenericKey will only populate the scheme to eui64Scheme, it will be left as 0 otherwise
	if isExtended = scheme == eui64Scheme; isExtended {
		segCount = ExtendedUniqueIdentifier64SegmentCount
	}
	return NewMACAddressFromRangeExt(
		func(segmentIndex int) MACSegInt {
			valsIndex := segmentIndex >> 3
			segIndex := ((segCount - 1) - segmentIndex) & 0x7
			return MACSegInt(key.vals[valsIndex].lower >> (segIndex << macBitsToSegmentBitshift))
		}, func(segmentIndex int) MACSegInt {
			valsIndex := segmentIndex >> 3
			segIndex := ((segCount - 1) - segmentIndex) & 0x7
			return MACSegInt(key.vals[valsIndex].upper >> (segIndex << macBitsToSegmentBitshift))
		},
		isExtended,
	)
}
