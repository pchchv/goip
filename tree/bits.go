package tree

// A PrefixBitCount is the count of bits in a non-nil PrefixLen.
type PrefixBitCount uint8

// A BitCount represents a count of bits in an address, section, grouping, segment, or division.
// Using signed integers allows for easier arithmetic, avoiding bugs.
// However, all methods adjust bit counts to match address size,
// so negative bit counts or bit counts larger than address size are meaningless.
type BitCount = int // using signed integers allows for easier arithmetic

// A PrefixLen indicates the length of the prefix for an address, section, division grouping, segment, or division.
// The zero value, which is nil, indicates that there is no prefix length.
type PrefixLen = *PrefixBitCount

// Len returns the length of the prefix.
// If the receiver is nil, representing the absence of a prefix length, returns 0.
// It will also return 0 if the receiver is a prefix with length of 0.
// To distinguish the two, compare the receiver with nil.
func (p *PrefixBitCount) Len() BitCount {
	if p == nil {
		return 0
	}
	return p.bitCount()
}

func (p *PrefixBitCount) bitCount() BitCount {
	return BitCount(*p)
}
