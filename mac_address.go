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
