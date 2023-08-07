package goip

import (
	"fmt"
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
