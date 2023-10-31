package tree

// A PrefixBitCount is the count of bits in a non-nil PrefixLen.
type PrefixBitCount uint8

// A BitCount represents a count of bits in an address, section, grouping, segment, or division.
// Using signed integers allows for easier arithmetic, avoiding bugs.
// However, all methods adjust bit counts to match address size,
// so negative bit counts or bit counts larger than address size are meaningless.
type BitCount = int // using signed integers allows for easier arithmetic
