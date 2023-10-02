package goip

import (
	"fmt"
	"math/big"
)

var zeroLargeGrouping = createLargeGrouping(zeroLargeDivs)

type largeDivisionGroupingInternal struct {
	addressDivisionGroupingBase
}

func (grouping *largeDivisionGroupingInternal) calcBytes() (bytes, upperBytes []byte) {
	divisionCount := grouping.GetDivisionCount()
	isMultiple := grouping.isMultiple()
	byteCount := grouping.GetByteCount()
	bytes = make([]byte, byteCount)

	if isMultiple {
		upperBytes = make([]byte, byteCount)
	} else {
		upperBytes = bytes
	}

	for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
		div := grouping.getDivision(k)
		bigBytes := div.getValue().Bytes()
		var bigUpperBytes []byte

		if isMultiple {
			bigUpperBytes = div.getUpperValue().Bytes()
		}

		for totalDivBits := div.GetBitCount(); totalDivBits > 0; totalDivBits -= 64 {
			// grab those 64 bits (from bigBytes and bigUpperBytes) and put them in val and upperVal
			divBits := min(totalDivBits, 64)
			var divBytes []byte
			var val, upperVal uint64

			if len(bigBytes) > 8 {
				byteLen := len(bigBytes) - 8
				divBytes = bigBytes[byteLen:]
				bigBytes = bigBytes[:byteLen]
			} else {
				divBytes = bigBytes
				bigBytes = nil
			}

			for _, b := range divBytes {
				val = (val << 8) | uint64(b)
			}

			if isMultiple {
				var divUpperBytes []byte
				if len(upperBytes) > 8 {
					byteLen := len(bigUpperBytes) - 8
					divUpperBytes = bigBytes[byteLen:]
					bigUpperBytes = bigBytes[:byteLen]
				} else {
					divUpperBytes = bigUpperBytes
					bigUpperBytes = nil
				}

				for _, b := range divUpperBytes {
					upperVal = (upperVal << 8) | uint64(b)
				}
			}

			// insert the 64 bits into the  bytes slice
			for divBits > 0 {
				rbi := 8 - bitIndex
				bytes[byteIndex] |= byte(val << uint(rbi))
				val >>= uint(bitIndex)

				if isMultiple {
					upperBytes[byteIndex] |= byte(upperVal << uint(rbi))
					upperVal >>= uint(bitIndex)
				}

				if divBits < bitIndex {
					// bitIndex is the index into the last copied byte that was already occupied previously
					// so here we were able to copy all the bits and there was still space left over
					bitIndex -= divBits
					break
				} else {
					// we used up all the space available
					// if we also copied all the bits, then divBits will be assigned zero
					// otherwise it will have the number of bits still left to copy
					divBits -= bitIndex
					bitIndex = 8
					byteIndex--
				}
			}
		}
	}
	return
}

func (grouping *largeDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getCachedBytes(grouping.calcBytes)
	return
}

// CopyUpperBytes copies the value of the highest division grouping in the range into a byte slice.
//
// If the value can fit in the given slice, it is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice with the value is created and returned.
//
// You can use the GetByteCount function to determine the required length of the byte array.
func (grouping *largeDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes[:0]
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getUpperBytes())
}

// UpperBytes returns the highest individual division grouping in this grouping as a byte slice.
func (grouping *largeDivisionGroupingInternal) UpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	return cloneBytes(grouping.getUpperBytes())
}

// GetUpperValue returns the highest individual address division grouping
// in this address division grouping as an integer value.
func (grouping *largeDivisionGroupingInternal) GetUpperValue() *big.Int {
	res := big.Int{}
	if grouping.hasNoDivisions() {
		return &res
	}
	return res.SetBytes(grouping.getUpperBytes())
}

func (grouping *largeDivisionGroupingInternal) getBytes() (bytes []byte) {
	bytes, _ = grouping.getCachedBytes(grouping.calcBytes)
	return
}

// Bytes returns the lowest individual division grouping in this grouping as a byte slice.
func (grouping *largeDivisionGroupingInternal) Bytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	return cloneBytes(grouping.getBytes())
}

func (grouping *largeDivisionGroupingInternal) getDivArray() largeDivArray {
	if divsArray := grouping.divisions; divsArray != nil {
		return divsArray.(largeDivArray)
	}
	return nil
}

func (grouping *largeDivisionGroupingInternal) getDivisionCount() int {
	if divArray := grouping.getDivArray(); divArray != nil {
		return divArray.getDivisionCount()
	}
	return 0
}

// getDivision returns the division or panics if the index is negative or too large
func (grouping *largeDivisionGroupingInternal) getDivision(index int) *IPAddressLargeDivision {
	return grouping.getDivArray()[index]
}

func (grouping *largeDivisionGroupingInternal) initMultiple() {
	divCount := grouping.getDivisionCount()
	for i := divCount - 1; i >= 0; i-- {
		div := grouping.getDivision(i)
		if div.isMultiple() {
			grouping.isMult = true
			return
		}
	}
	return
}

func (grouping *largeDivisionGroupingInternal) initDivs() *largeDivisionGroupingInternal {
	if grouping.divisions == nil {
		return &zeroLargeGrouping.largeDivisionGroupingInternal
	}
	return grouping
}

// divisions are printed like slices of *IPAddressLargeDivision (which are Stringers)
// with division separated by spaces and enclosed in square brackets,
// sections are printed like addresses with segments separated by segment separators
func (grouping largeDivisionGroupingInternal) Format(state fmt.State, verb rune) {
	arr := grouping.initDivs().getDivArray()
	if len(arr) == 0 {
		return
	}
	s := flagsFromState(state, verb)
	_, _ = state.Write([]byte(fmt.Sprintf(s, arr)))
}

func (grouping *largeDivisionGroupingInternal) toString() string {
	return fmt.Sprint(grouping.initDivs().getDivArray())
}

// CopyBytes copies the value of the lowest division grouping in the range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
//
// You can use GetByteCount to determine the required array length for the bytes.
func (grouping *largeDivisionGroupingInternal) CopyBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes[:0]
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getBytes())
}

// GetValue returns the lowest individual address division grouping in this address division grouping as an integer value.
func (grouping *largeDivisionGroupingInternal) GetValue() *big.Int {
	res := big.Int{}
	if grouping.hasNoDivisions() {
		return &res
	}
	return res.SetBytes(grouping.getBytes())
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that
// this grouping includes the block of all values for that prefix length.
//
// If the entire range can be described this way,
// then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix,
// or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this grouping represents a single value, this returns the bit count.
func (grouping *largeDivisionGroupingInternal) GetMinPrefixLenForBlock() BitCount {
	calc := func() BitCount {
		count := grouping.GetDivisionCount()
		totalPrefix := grouping.GetBitCount()
		for i := count - 1; i >= 0; i-- {
			div := grouping.getDivision(i)
			segBitCount := div.getBitCount()
			segPrefix := div.GetMinPrefixLenForBlock()
			if segPrefix == segBitCount {
				break
			} else {
				totalPrefix -= segBitCount
				if segPrefix != 0 {
					totalPrefix += segPrefix
					break
				}
			}
		}
		return totalPrefix
	}
	return cacheMinPrefix(grouping.cache, calc)
}

// ContainsPrefixBlock returns whether the values of this item contains the block of values for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (grouping *largeDivisionGroupingInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	var prevBitCount BitCount
	prefixLen = checkSubnet(grouping, prefixLen)
	divisionCount := grouping.GetDivisionCount()
	for i := 0; i < divisionCount; i++ {
		division := grouping.getDivision(i)
		bitCount := division.GetBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen < totalBitCount {
			divPrefixLen := prefixLen - prevBitCount
			if !division.ContainsPrefixBlock(divPrefixLen) {
				return false
			}
			for i++; i < divisionCount; i++ {
				division = grouping.getDivision(i)
				if !division.IsFullRange() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

type IPAddressLargeDivisionGrouping struct {
	largeDivisionGroupingInternal
}

// GetCount returns the count of possible distinct values for this division grouping.
// If not representing multiple values, the count is 1,
// unless this is a division grouping with no divisions,
// or an address section with no segments, in which case it is 0.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (grouping *IPAddressLargeDivisionGrouping) GetCount() *big.Int {
	if !grouping.isMultiple() {
		return bigOne()
	}
	return grouping.addressDivisionGroupingBase.getCount()
}

// IsMultiple returns whether this grouping represents multiple values rather than a single value.
func (grouping *IPAddressLargeDivisionGrouping) IsMultiple() bool {
	return grouping != nil && grouping.isMultiple()
}

// IsPrefixed returns whether this division grouping has an associated prefix length.
// If so, the prefix length is given by GetPrefixLen.
func (grouping *IPAddressLargeDivisionGrouping) IsPrefixed() bool {
	if grouping == nil {
		return false
	}
	return grouping.isPrefixed()
}

func (grouping *IPAddressLargeDivisionGrouping) isNil() bool {
	return grouping == nil
}

func normalizeLargeDivisions(divs []*IPAddressLargeDivision) (newDivs []*IPAddressLargeDivision, newPref PrefixLen, isMultiple bool) {
	var previousDivPrefixed bool
	var bits BitCount
	divCount := len(divs)
	newDivs = make([]*IPAddressLargeDivision, 0, divCount)

	for _, div := range divs {
		if div == nil || div.GetBitCount() == 0 {
			continue
		}

		var newDiv *IPAddressLargeDivision
		// The final prefix length is the minimum amongst the divisions' own prefixes
		divPrefix := div.getDivisionPrefixLength()
		divIsPrefixed := divPrefix != nil

		if previousDivPrefixed {
			if !divIsPrefixed || divPrefix.bitCount() != 0 {
				newDiv = createLargeAddressDiv(div.derivePrefixed(cacheBitCount(0)), div.getDefaultRadix()) // change prefix to 0
			} else {
				newDiv = div // div prefix is already 0
			}
		} else {
			if divIsPrefixed {
				if divPrefix.bitCount() == 0 && len(newDivs) > 0 {
					// normalize boundaries by looking back
					lastDiv := newDivs[len(newDivs)-1]
					if !lastDiv.IsPrefixed() {
						newDivs[len(newDivs)-1] = createLargeAddressDiv(
							lastDiv.derivePrefixed(cacheBitCount(lastDiv.GetBitCount())), div.getDefaultRadix())
					}
				}
				newPref = cacheBitCount(bits + divPrefix.bitCount())
				previousDivPrefixed = true
			}
			newDiv = div
		}

		newDivs = append(newDivs, newDiv)
		bits += newDiv.GetBitCount()
		isMultiple = isMultiple || newDiv.isMultiple()
	}
	return
}

func createLargeGrouping(divs []*IPAddressLargeDivision) *IPAddressLargeDivisionGrouping {
	addrType := zeroType
	grouping := &IPAddressLargeDivisionGrouping{
		largeDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions: largeDivArray(divs),
				addrType:  addrType,
				cache:     &valueCache{},
			},
		},
	}
	assignStringCache(&grouping.addressDivisionGroupingBase, addrType)
	return grouping
}

// NewIPAddressLargeDivGrouping creates an arbitrary grouping of divisions of arbitrary size,
// each division can have an arbitrarily large bit-length.
// To create address sections or addresses, use the constructors that are specific to the address version or type.
// The IPAddressLargeDivision instances can be created with the
// NewLargeIPDivision, NewLargeIPRangeDivision, NewLargeIPPrefixDivision, NewLargeIPRangePrefixDivision functions.
func NewIPAddressLargeDivGrouping(divs []*IPAddressLargeDivision) *IPAddressLargeDivisionGrouping {
	// We do not check for prefix subnet because an explicit prefix length must be supplied for that
	newDivs, newPref, isMult := normalizeLargeDivisions(divs)
	result := createLargeGrouping(newDivs)
	result.isMult = isMult
	result.prefixLength = newPref
	return result
}
