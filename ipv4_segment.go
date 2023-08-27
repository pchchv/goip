package goip

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
