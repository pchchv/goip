package goip

import (
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

const (
	uninitializedType ipType = iota
	invalidType
	emptyType
	ipv4AddrType
	ipv6AddrType
	allType
)

var (
	invalidProvider = &nullProvider{isInvalidVal: true, ipType: invalidType}
	emptyProvider   = &nullProvider{isEmpty: true, ipType: emptyType}
)

// All IP address strings corresponds to exactly one of these types.
// In cases where there is no corresponding default IPAddress value
// (invalidType, allType, and possibly emptyType), these types can be used for comparison.
// emptyType means a zero-length string (useful for validation, we can set validation to allow empty strings)
// that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
// invalidType means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
// allType means it is wildcard(s) with no separators, like "*",
// which represents all addresses, whether IPv4, IPv6 or other,
// and thus has no corresponding IPAddress value
// These constants are ordered by address space size, from smallest to largest, and the ordering affects comparisons
type ipType int

func fromVersion(version IPVersion) ipType {
	switch version {
	case IPv4:
		return ipv4AddrType
	case IPv6:
		return ipv6AddrType
	}
	return uninitializedType
}

func (t ipType) isUnknown() bool {
	return t == uninitializedType
}

type ipAddressProvider interface {
	getType() ipType
	getProviderHostAddress() (*IPAddress, address_error.IncompatibleAddressError)
	getProviderAddress() (*IPAddress, address_error.IncompatibleAddressError)
	getVersionedAddress(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError)
	isSequential() bool
	getProviderSeqRange() *SequentialRange[*IPAddress]
	getProviderMask() *IPAddress
	providerCompare(ipAddressProvider) (int, address_error.IncompatibleAddressError)
	providerEquals(ipAddressProvider) (bool, address_error.IncompatibleAddressError)
	getProviderIPVersion() IPVersion
	isProvidingIPAddress() bool
	isProvidingIPv4() bool
	isProvidingIPv6() bool
	isProvidingAllAddresses() bool // providing **all** addresses of any IP version, ie "*", not "*.*" or "*:*"
	isProvidingEmpty() bool
	isProvidingMixedIPv6() bool
	isProvidingBase85IPv6() bool
	getProviderNetworkPrefixLen() PrefixLen
	isInvalid() bool
	// If the address was created by parsing, this provides the parameters used when creating the address,
	// otherwise nil
	getParameters() address_string_param.IPAddressStringParams
	// containsProvider is an optimized contains that does not need to create address objects to return an answer.
	// Unconventional addresses may require that the address objects are created, in such cases nil is returned.
	//
	// Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	containsProvider(ipAddressProvider) boolSetting
	// prefixEqualsProvider is an optimized prefix comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	prefixEqualsProvider(ipAddressProvider) boolSetting
	// prefixContainsProvider is an optimized prefix comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	prefixContainsProvider(ipAddressProvider) boolSetting
	// parsedEquals is an optimized equality comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	parsedEquals(ipAddressProvider) boolSetting
}

type ipAddrProvider struct{}

func (p *ipAddrProvider) getType() ipType {
	return uninitializedType
}

func (p *ipAddrProvider) isSequential() bool {
	return false
}

func (p *ipAddrProvider) getProviderHostAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderSeqRange() *SequentialRange[*IPAddress] {
	return nil
}

func (p *ipAddrProvider) getVersionedAddress(_ IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderMask() *IPAddress {
	return nil
}

func (p *ipAddrProvider) getProviderIPVersion() IPVersion {
	return IndeterminateIPVersion
}

func (p *ipAddrProvider) isProvidingIPAddress() bool {
	return false
}

func (p *ipAddrProvider) isProvidingIPv4() bool {
	return false
}

func (p *ipAddrProvider) isProvidingIPv6() bool {
	return false
}

func (p *ipAddrProvider) isProvidingAllAddresses() bool {
	return false
}

func (p *ipAddrProvider) isProvidingEmpty() bool {
	return false
}

func (p *ipAddrProvider) isInvalid() bool {
	return false
}

func (p *ipAddrProvider) isProvidingMixedIPv6() bool {
	return false
}

func (p *ipAddrProvider) isProvidingBase85IPv6() bool {
	return false
}

func (p *ipAddrProvider) getProviderNetworkPrefixLen() PrefixLen {
	return nil
}

func (p *ipAddrProvider) getParameters() address_string_param.IPAddressStringParams {
	return nil
}

func (p *ipAddrProvider) containsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixEqualsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixContainsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) parsedEquals(ipAddressProvider) boolSetting {
	return boolSetting{}
}

type nullProvider struct {
	ipAddrProvider
	ipType       ipType
	isEmpty      bool
	isInvalidVal bool
	params       address_string_param.IPAddressStringParams
}

func (p *nullProvider) isInvalid() bool {
	return p.isInvalidVal
}

func (p *nullProvider) isProvidingEmpty() bool {
	return p.isEmpty
}

type addressResult struct {
	address       *IPAddress
	hostAddress   *IPAddress
	address_Error address_error.IncompatibleAddressError
	hostErr       address_error.IncompatibleAddressError
	rng           *SequentialRange[*IPAddress] // only used when no address can be obtained
}

type cachedAddressProvider struct {
	ipAddrProvider
	// addressCreator creates two addresses, the host address and address with prefix/mask, at the same time
	addressCreator func() (address, hostAddress *IPAddress, address_Error, hosterr address_error.IncompatibleAddressError)
	addresses      *addressResult
}

func (cached *cachedAddressProvider) isProvidingIPAddress() bool {
	return true
}

func (cached *cachedAddressProvider) isSequential() bool {
	addr, _ := cached.getProviderAddress()
	if addr != nil {
		return addr.IsSequential()
	}
	return false
}

func (cached *cachedAddressProvider) getVersionedAddress(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
	thisVersion := cached.getProviderIPVersion()
	if version != thisVersion {
		return nil, nil
	}
	return cached.getProviderAddress()
}

func (cached *cachedAddressProvider) getType() ipType {
	return fromVersion(cached.getProviderIPVersion())
}

func (cached *cachedAddressProvider) getCachedAddresses() (address, hostAddress *IPAddress, address_Error, hostErr address_error.IncompatibleAddressError) {
	addrs := (*addressResult)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cached.addresses))))
	if addrs == nil {
		if cached.addressCreator != nil {
			address, hostAddress, address_Error, hostErr = cached.addressCreator()
			addresses := &addressResult{
				address:       address,
				hostAddress:   hostAddress,
				address_Error: address_Error,
				hostErr:       hostErr,
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cached.addresses))
			atomicStorePointer(dataLoc, unsafe.Pointer(addresses))
		}
	} else {
		address, hostAddress, address_Error, hostErr = addrs.address, addrs.hostAddress, addrs.address_Error, addrs.hostErr
	}
	return
}

type versionedAddressCreator struct {
	cachedAddressProvider
	adjustedVersion             IPVersion
	versionedAddressCreatorFunc func(IPVersion) (*IPAddress, address_error.IncompatibleAddressError)
	versionedValues             [2]*IPAddress
	parameters                  address_string_param.IPAddressStringParams
}
