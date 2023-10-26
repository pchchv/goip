package goip

// SequentialRangeKey is a representation of SequentialRange that is comparable as defined by the language specification.
//
// It can be used as a map key.
// The zero value is a range from a zero-length address to itself.
type SequentialRangeKey[T SequentialRangeConstraint[T]] struct {
	vals [2]struct {
		lower,
		upper uint64
	}
	addrType addrType // only used when T is *IPAddress to indicate version for non-zero valued address
}
