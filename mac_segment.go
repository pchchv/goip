package goip

// MACAddressSegment represents a segment of a MAC address.
// For MAC, segments are 1 byte.
// A MAC segment contains a single value or a range of sequential values,
// a prefix length, and it has bit length of 8 bits.
//
// Segments are immutable, which also makes them concurrency-safe.
type MACAddressSegment struct {
	addressSegmentInternal
}
