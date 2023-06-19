package goip

import "fmt"

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
