package goip

import (
	"math"
	"math/big"
	"strconv"
)

const (
	maxBitCountInternal = math.MaxUint8
	minBitCountInternal = 0
)

var (
	one                                     = bigOne()
	zero                                    = bigZero()
	minusOne                                = big.NewInt(-1)
	falseVal                                = false
	trueVal                                 = true
	cachedPrefixBitCounts, cachedPrefixLens = initPrefLens()
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

// Matches compares a PrefixLen value with a bit count
func (prefixBitCount *PrefixBitCount) Matches(other BitCount) bool {
	return prefixBitCount != nil && prefixBitCount.bitCount() == other
}

// Equal compares two PrefixLen values for equality.  This method is intended for the PrefixLen type.  BitCount values should be compared with the == operator.
func (prefixBitCount *PrefixBitCount) Equal(other PrefixLen) bool {
	if prefixBitCount == nil {
		return other == nil
	}
	return other != nil && prefixBitCount.bitCount() == other.bitCount()
}

// String returns the bit count as a base-10 positive integer string, or "<nil>" if the receiver is a nil pointer.
func (prefixBitCount *PrefixBitCount) String() string {
	if prefixBitCount == nil {
		return nilString()
	}
	return strconv.Itoa(prefixBitCount.bitCount())
}

// Compare compares PrefixLen values, returning -1, 0, or 1 if this prefix length is less than, equal to, or greater than the given prefix length.
// This method is intended for the PrefixLen type.
// BitCount values should be compared with ==, >, <, >= and <= operators.
func (prefixBitCount *PrefixBitCount) Compare(other PrefixLen) int {
	if prefixBitCount == nil {
		if other == nil {
			return 0
		}
		return 1
	} else if other == nil {
		return -1
	}
	return prefixBitCount.bitCount() - other.bitCount()
}

func (prefixBitCount *PrefixBitCount) bitCount() BitCount {
	return BitCount(*prefixBitCount)
}

func (prefixBitCount *PrefixBitCount) copy() PrefixLen {
	if prefixBitCount == nil {
		return nil
	}

	res := *prefixBitCount

	return &res
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

func bigSixteen() *big.Int {
	return big.NewInt(16)
}

// ToPrefixLen converts the given int to a prefix length
func ToPrefixLen(i int) PrefixLen {
	res := PrefixBitCount(i)
	return &res
}

func checkSubnet(item BitItem, prefixLength BitCount) BitCount {
	return checkBitCount(prefixLength, item.GetBitCount())
}

func checkDiv(div DivisionType, prefixLength BitCount) BitCount {
	return checkBitCount(prefixLength, div.GetBitCount())
}

func checkBitCount(prefixLength, max BitCount) BitCount {
	if prefixLength > max {
		return max
	} else if prefixLength < 0 {
		return 0
	}
	return prefixLength
}

func initPrefLens() ([]PrefixBitCount, []PrefixLen) {
	cachedPrefBitcounts := make([]PrefixBitCount, maxBitCountInternal)
	cachedPrefLens := make([]PrefixLen, maxBitCountInternal)

	for i := 0; i <= IPv6BitCount; i++ {
		cachedPrefBitcounts[i] = PrefixBitCount(i)
		cachedPrefLens[i] = &cachedPrefBitcounts[i]
	}

	return cachedPrefBitcounts, cachedPrefLens
}

func cacheBitCount(i BitCount) PrefixLen {
	if i < minBitCountInternal {
		i = minBitCountInternal
	}

	if i < len(cachedPrefixBitCounts) {
		return &cachedPrefixBitCounts[i]
	}

	if i > maxBitCountInternal {
		i = maxBitCountInternal
	}

	res := PrefixBitCount(i)

	return &res
}

func bigAbsIsOne(val *BigDivInt) bool {
	bits := val.Bits()
	return len(bits) == 1 && bits[0] == 1
}

func bigIsOne(val *BigDivInt) bool {
	return bigAbsIsOne(val) && val.Sign() > 0
}
