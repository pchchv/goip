package goip

import "math/big"

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
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *MACAddress) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

func getMacSegCount(isExtended bool) (segmentCount int) {
	if isExtended {
		segmentCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		segmentCount = MediaAccessControlSegmentCount
	}
	return
}
