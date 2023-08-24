package goip

import (
	"fmt"
	"math/big"
	"unsafe"
)

var (
	zeroDivs                      = make([]*AddressDivision, 0)
	zeroStandardDivArray          = standardDivArray(zeroDivs)
	zeroLargeDivs                 = make([]*IPAddressLargeDivision, 0)
	zeroLargeDivArray             = largeDivArray(zeroLargeDivs)
	_                    divArray = standardDivArray{}
)

type ipStringCache struct {
	normalizedWildcardString,
	fullString,
	sqlWildcardString,
	reverseDNSString,
	segmentedBinaryString *string
}

type ipv4StringCache struct {
	inetAtonOctalString,
	inetAtonHexString *string
}

type ipv6StringCache struct {
	normalizedIPv6String,
	compressedIPv6String,
	mixedString,
	compressedWildcardString,
	canonicalWildcardString,
	networkPrefixLengthString,
	base85String,
	uncString *string
}

type macStringCache struct {
	normalizedMACString,
	compressedMACString,
	dottedString,
	spaceDelimitedString *string
}

type stringCache struct {
	canonicalString,
	octalString,
	octalStringPrefixed,
	binaryString,
	binaryStringPrefixed,
	hexString,
	hexStringPrefixed *string
	*ipv6StringCache
	*ipv4StringCache
	*ipStringCache
	*macStringCache
}

type divArray interface {
	getDivision(index int) *addressDivisionBase
	getGenericDivision(index int) DivisionType
	getDivisionCount() int
	fmt.Stringer
}

type maskLenSetting struct {
	networkMaskLen PrefixLen
	hostMaskLen    PrefixLen
}

type bytesCache struct {
	lowerBytes []byte
	upperBytes []byte
}

type groupingCache struct {
	lower *AddressSection
	upper *AddressSection
}

type mixedCache struct {
	defaultMixedAddressSection *IPv6v4MixedAddressGrouping
	embeddedIPv4Section        *IPv4AddressSection
	embeddedIPv6Section        *EmbeddedIPv6AddressSection
}

type valueCache struct {
	cachedCount         *big.Int
	cachedPrefixCount   *big.Int
	cachedMaskLens      *maskLenSetting
	bytesCache          *bytesCache
	stringCache         stringCache
	sectionCache        *groupingCache
	mixed               *mixedCache
	minPrefix           PrefixLen
	equivalentPrefix    *PrefixLen
	isSinglePrefixBlock *bool
}

type standardDivArray []*AddressDivision

func (grouping standardDivArray) String() string {
	return fmt.Sprint([]*AddressDivision(grouping.init()))
}

func (grouping standardDivArray) getDivisionCount() int {
	return len(grouping)
}

func (grouping standardDivArray) getDivision(index int) *addressDivisionBase {
	return (*addressDivisionBase)(unsafe.Pointer(grouping[index]))
}

func (grouping standardDivArray) copyDivisions(divs []*AddressDivision) (count int) {
	return copy(divs, grouping)
}

func (grouping standardDivArray) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return copy(divs, grouping[start:end])
}

func (grouping standardDivArray) getSubDivisions(index, endIndex int) (divs []*AddressDivision) {
	return grouping[index:endIndex]
}

func (grouping standardDivArray) init() standardDivArray {
	if grouping == nil {
		return zeroStandardDivArray
	}
	return grouping
}

func (grouping standardDivArray) getGenericDivision(index int) DivisionType {
	return grouping[index]
}

type largeDivArray []*IPAddressLargeDivision

func (grouping largeDivArray) getDivisionCount() int {
	return len(grouping)
}

func (grouping largeDivArray) getDivision(index int) *addressDivisionBase {
	return (*addressDivisionBase)(unsafe.Pointer(grouping[index]))
}

func (grouping largeDivArray) copyDivisions(divs []*IPAddressLargeDivision) (count int) {
	return copy(divs, grouping)
}

func (grouping largeDivArray) copySubDivisions(start, end int, divs []*IPAddressLargeDivision) (count int) {
	return copy(divs, grouping[start:end])
}

func (grouping largeDivArray) init() largeDivArray {
	if grouping == nil {
		return zeroLargeDivArray
	}
	return grouping
}

func (grouping largeDivArray) getSubDivisions(index, endIndex int) (divs []*IPAddressLargeDivision) {
	return grouping[index:endIndex]
}

func (grouping largeDivArray) String() string {
	return fmt.Sprint([]*IPAddressLargeDivision(grouping.init()))
}

type addressDivisionGroupingBase struct {
	// the non-cacheBitCount elements are assigned at creation and are immutable
	divisions    divArray  // either standard or large
	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMult       bool
	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels,
	// such as functions returning strings, can rely on this field.
	addrType addrType
	// assigned on creation only; for zero-value groupings it is never assigned,
	// but in that case it is not needed since there is nothing to cache
	cache *valueCache
}

func (grouping *addressDivisionGroupingBase) getAddrType() addrType {
	return grouping.addrType
}

func (grouping *addressDivisionGroupingBase) getPrefixLen() PrefixLen {
	return grouping.prefixLength
}

func (grouping *addressDivisionGroupingBase) isPrefixed() bool {
	return grouping.prefixLength != nil
}

// isMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingBase) isMultiple() bool {
	return grouping.isMult
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when constructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingBase) hasNoDivisions() bool {
	divisions := grouping.divisions
	return divisions == nil || divisions.getDivisionCount() == 0
}

// getDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingBase) getDivision(index int) *addressDivisionBase {
	return grouping.divisions.getDivision(index)
}

func (grouping *addressDivisionGroupingBase) calcCount(counter func() *big.Int) *big.Int {
	if grouping != nil && !grouping.isMultiple() {
		return bigOne()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) calcUint64Count(counter func() uint64) uint64 {
	if grouping != nil && !grouping.isMultiple() {
		return 1
	}
	return counter()
}

// cachedCount returns the cached count value, not a duplicate.
func (grouping *addressDivisionGroupingBase) cachedCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache
	if cache == nil {
		return grouping.calcCount(counter)
	}

	count := (*big.Int)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))))
	if count == nil {
		count = grouping.calcCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomicStorePointer(dataLoc, unsafe.Pointer(count))
	}

	return count
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache
	if cache == nil {
		return grouping.calcCount(counter)
	}

	count := (*big.Int)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))))
	if count == nil {
		count = grouping.calcCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomicStorePointer(dataLoc, unsafe.Pointer(count))
	}

	return new(big.Int).Set(count)
}

// GetDivisionCount returns the number of divisions in this grouping.
func (grouping *addressDivisionGroupingBase) GetDivisionCount() int {
	divisions := grouping.divisions
	if divisions != nil {
		return divisions.getDivisionCount()
	}
	return 0
}

func (grouping *addressDivisionGroupingBase) getCountBig() *big.Int {
	res := bigOne()
	count := grouping.GetDivisionCount()
	if count > 0 {
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			if div.isMultiple() {
				res.Mul(res, div.getCount())
			}
		}
	}
	return res
}
