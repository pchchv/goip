package goip

var emptyBytes = make([]byte, 0, 0)

type addressDivisionGroupingInternal struct {
	addressDivisionGroupingBase
}

// The adaptive zero grouping, produced by zero sections like IPv4AddressSection{} or AddressDivisionGrouping{},
// can represent a zero-length section of any address type,
// It is not considered equal to constructions of specific zero length sections of groupings like
// NewIPv4Section(nil) which can only represent a zero-length section of a single address type.
func (grouping *addressDivisionGroupingInternal) matchesZeroGrouping() bool {
	addrType := grouping.getAddrType()
	return addrType.isZeroSegments() && grouping.hasNoDivisions()
}

// AddressDivisionGrouping objects consist of a series of AddressDivision objects,
// each containing a consistent range of values.
//
// AddressDivisionGrouping objects are immutable.
// This also makes them concurrency-safe.
//
// AddressDivision objects use uint64 to represent their values,
// so this places a limit on the size of the divisions in AddressDivisionGrouping.
//
// AddressDivisionGrouping objects are similar to address sections and addresses,
// except that groupings can have divisions of different bit-lengths,
// including divisions that are not the exact number of bytes,
// whereas all segments in an address or address section must have the same bit size and exact number of bytes.
type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}
