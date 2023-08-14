package goip

import (
	"sync"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

type translatedResult struct {
	sections *sectionResult
	rng      *SequentialRange[*IPAddress]
	mask     *IPAddress
}

type boundaryResult struct {
	lowerSection *IPAddressSection
	upperSection *IPAddressSection
}

type sectionResult struct {
	section          *IPAddressSection
	hostSection      *IPAddressSection
	address          *IPAddress
	hostAddress      *IPAddress
	joinHostError    address_error.IncompatibleAddressError
	joinAddressError address_error.IncompatibleAddressError
	mixedError       address_error.IncompatibleAddressError
	maskError        address_error.IncompatibleAddressError
}

func (res *sectionResult) withoutAddressException() bool {
	return res.joinAddressError == nil && res.mixedError == nil && res.maskError == nil
}

type parsedIPAddress struct {
	ipAddressParseData
	ipAddrProvider // provides a few methods like isInvalid
	options        address_string_param.IPAddressStringParams
	originator     HostIdentifierString
	vals           translatedResult
	skipCntains    *bool
	maskers        []Masker
	mixedMaskers   []Masker
	creationLock   sync.Mutex
}

func (parseData *parsedIPAddress) values() *translatedResult {
	return &parseData.vals
}

func (parseData *parsedIPAddress) isProvidingIPAddress() bool {
	return true
}

func (parseData *parsedIPAddress) getParameters() address_string_param.IPAddressStringParams {
	return parseData.options
}

func (parseData *parsedIPAddress) isProvidingMixedIPv6() bool {
	return parseData.ipAddressParseData.isProvidingMixedIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv6() bool {
	return parseData.ipAddressParseData.isProvidingIPv6()
}

func (parseData *parsedIPAddress) isProvidingIPv4() bool {
	return parseData.ipAddressParseData.isProvidingIPv4()
}

func (parseData *parsedIPAddress) isProvidingBase85IPv6() bool {
	return parseData.ipAddressParseData.isProvidingBase85IPv6()
}

func (parseData *parsedIPAddress) getProviderIPVersion() IPVersion {
	return parseData.ipAddressParseData.getProviderIPVersion()
}

func (parseData *parsedIPAddress) getIPAddressParseData() *ipAddressParseData {
	return &parseData.ipAddressParseData
}

func (parseData *parsedIPAddress) getVersionedAddress(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
	thisVersion := parseData.getProviderIPVersion()

	if version != thisVersion {
		return nil, nil
	}

	return parseData.getProviderAddress()
}
