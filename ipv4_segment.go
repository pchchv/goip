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

func (seg *ipv4SegmentValues) getByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *ipv4SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv4SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv4SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv4SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *ipv4SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

func (seg *ipv4SegmentValues) bytesInternal(upper bool) []byte {
	if upper {
		return []byte{byte(seg.upperValue)}
	}
	return []byte{byte(seg.value)}
}
