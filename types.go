package goip

// BitCount is a bit count of an address, section, grouping, segment or division.
// Using signed integers simplifies arithmetic by avoiding errors.
// However, all methods adjust the number of bits according to the address size,
// so negative numbers of bits or numbers of bits greater than the address size are meaningless.
// Using signed integers allows you to simplify arithmetic.
type BitCount = int

// PrefixBitCount is the number of bits in a non-zero PrefixLen.
// For arithmetic you can use the signed integer type BitCount,
// which you can get from PrefixLen using the Len method.
type PrefixBitCount uint8

// PrefixLen indicates the prefix length for an address, section, division group, segment or division.
// A value of zero, i.e. nil, indicates that there is no prefix length.
type PrefixLen = *PrefixBitCount
