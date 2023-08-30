package goip

import "math/big"

type IPv4SegInt = uint8

type IPv4SegmentValueProvider func(segmentIndex int) IPv4SegInt

// IPv4AddressSegment represents a segment of an IPv4 address.
// An IPv4 segment contains a single value or a range of sequential values,
// a prefix length, and it has bit length of 8 bits.
//
// Like strings, segments are immutable, which also makes them concurrency-safe.
//
// See AddressSegment for more details regarding segments.
type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

type ipv4SegmentValues struct {
	value      IPv4SegInt
	upperValue IPv4SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv4SegmentValues) getAddrType() addrType {
	return ipv4Type
}

func (seg *ipv4SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv4SegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg *ipv4SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv4SegmentValues) getCount() *big.Int {
	return big.NewInt(int64(seg.upperValue-seg.value) + 1)
}

func (seg *ipv4SegmentValues) getBitCount() BitCount {
	return IPv4BitsPerSegment
}
