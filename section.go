package goip

type addressSectionInternal struct {
	addressDivisionGroupingInternal
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
