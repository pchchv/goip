package goip

const (
	maxBitCountInternal = math.MaxUint8
	minBitCountInternal = 0
)

var (
	one      = bigOne()
	zero     = bigZero()
	minusOne = big.NewInt(-1)
)

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

// Len returns the length of the prefix.  If the receiver is nil, representing the absence of a prefix length, returns 0.
// It will also return 0 if the receiver is a prefix with length of 0.  To distinguish the two, compare the receiver with nil.
func (prefixBitCount *PrefixBitCount) Len() BitCount {
	if prefixBitCount == nil {
		return 0
	}
	return prefixBitCount.bitCount()
}

// IsNil returns true if this is nil, meaning it represents having no prefix length, or the absence of a prefix length
func (prefixBitCount *PrefixBitCount) IsNil() bool {
	return prefixBitCount == nil
}

func (prefixBitCount *PrefixBitCount) bitCount() BitCount {
	return BitCount(*prefixBitCount)
}

func bigIsZero(val *BigDivInt) bool {
	return len(val.Bits()) == 0 // slightly faster than div.value.BitLen() == 0
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

func bigOneConst() *big.Int {
	return one
}

func bigZero() *big.Int {
	return new(big.Int)
}

func bigZeroConst() *big.Int {
	return zero
}

func bigMinusOneConst() *big.Int {
	return minusOne
}

// ToPrefixLen converts the given int to a prefix length
func ToPrefixLen(i int) PrefixLen {
	res := PrefixBitCount(i)
	return &res
}
