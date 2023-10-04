package goip

import (
	"math/big"
	"net"
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

var zeroMAC = createMACZero(false)

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
