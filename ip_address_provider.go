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

func (p *nullProvider) getType() ipType {
	return p.ipType
}

func (p *nullProvider) providerCompare(other ipAddressProvider) (int, address_error.IncompatibleAddressError) {
	return providerCompare(p, other)
}

func (p *nullProvider) providerEquals(other ipAddressProvider) (bool, address_error.IncompatibleAddressError) {
	return providerEquals(p, other)
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

func (cached *cachedAddressProvider) getProviderHostAddress() (res *IPAddress, err address_error.IncompatibleAddressError) {
	_, res, _, err = cached.getCachedAddresses()
	return
}

func (cached *cachedAddressProvider) getProviderAddress() (res *IPAddress, err address_error.IncompatibleAddressError) {
	res, _, err, _ = cached.getCachedAddresses()
	return
}

func (cached *cachedAddressProvider) providerCompare(other ipAddressProvider) (int, address_error.IncompatibleAddressError) {
	return providerCompare(cached, other)
}

func (cached *cachedAddressProvider) providerEquals(other ipAddressProvider) (bool, address_error.IncompatibleAddressError) {
	return providerEquals(cached, other)
}

func (cached *cachedAddressProvider) isProvidingIPv4() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv4()
}

func (cached *cachedAddressProvider) isProvidingIPv6() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv6()
}

func (cached *cachedAddressProvider) getProviderNetworkPrefixLen() (p PrefixLen) {
	if addr, _ := cached.getProviderAddress(); addr != nil {
		p = addr.getNetworkPrefixLen()
	}
	return
}

func (cached *cachedAddressProvider) getProviderIPVersion() IPVersion {
	if addr, _ := cached.getProviderAddress(); addr != nil {
		return addr.getIPVersion()
	}
	return IndeterminateIPVersion
}

type versionedAddressCreator struct {
	cachedAddressProvider
	adjustedVersion             IPVersion
	versionedAddressCreatorFunc func(IPVersion) (*IPAddress, address_error.IncompatibleAddressError)
	versionedValues             [2]*IPAddress
	parameters                  address_string_param.IPAddressStringParams
}

func (versioned *versionedAddressCreator) getParameters() address_string_param.IPAddressStringParams {
	return versioned.parameters
}

func (versioned *versionedAddressCreator) isProvidingIPAddress() bool {
	return versioned.adjustedVersion != IndeterminateIPVersion
}

func (versioned *versionedAddressCreator) isProvidingIPv4() bool {
	return versioned.adjustedVersion == IPv4
}

func (versioned *versionedAddressCreator) isProvidingIPv6() bool {
	return versioned.adjustedVersion == IPv6
}

func (versioned *versionedAddressCreator) getProviderIPVersion() IPVersion {
	return versioned.adjustedVersion
}

func (versioned *versionedAddressCreator) getType() ipType {
	return fromVersion(versioned.adjustedVersion)
}

func (versioned *versionedAddressCreator) getVersionedAddress(version IPVersion) (addr *IPAddress, err address_error.IncompatibleAddressError) {
	index := version.index()
	if index >= IndeterminateIPVersion.index() {
		return
	}

	if versioned.versionedAddressCreatorFunc != nil {
		addr = (*IPAddress)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&versioned.versionedValues[index]))))
		if addr == nil {
			addr, err = versioned.versionedAddressCreatorFunc(version)
			if err == nil {
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&versioned.versionedValues[index]))
				atomicStorePointer(dataLoc, unsafe.Pointer(addr))
			}
		}
		return
	}

	addr = versioned.versionedValues[index]
	return
}

type emptyAddrCreator struct {
	versionedAddressCreator
	zone Zone
}

func (loop *emptyAddrCreator) getProviderNetworkPrefixLen() PrefixLen {
	return nil
}

func (loop *emptyAddrCreator) providerCompare(other ipAddressProvider) (int, address_error.IncompatibleAddressError) {
	return providerCompare(loop, other)
}

func (loop *emptyAddrCreator) providerEquals(other ipAddressProvider) (bool, address_error.IncompatibleAddressError) {
	return providerEquals(loop, other)
}

type adjustedAddressCreator struct {
	versionedAddressCreator
	networkPrefixLength PrefixLen
}

func (adjusted *adjustedAddressCreator) getProviderNetworkPrefixLen() PrefixLen {
	return adjusted.networkPrefixLength
}

func (adjusted *adjustedAddressCreator) getProviderAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.versionedAddressCreator.getProviderAddress()
}

func (adjusted *adjustedAddressCreator) getProviderHostAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.versionedAddressCreator.getProviderHostAddress()
}

type maskCreator struct {
	adjustedAddressCreator
}

type allCreator struct {
	adjustedAddressCreator
	originator HostIdentifierString
	qualifier  parsedHostIdentifierStringQualifier
}

func (all *allCreator) getType() ipType {
	if !all.adjustedVersion.IsIndeterminate() {
		return fromVersion(all.adjustedVersion)
	}
	return allType
}

// isProvidingAllAddresses providing **all** addresses of any IP version,
// "*" not "*.*" or "*:*"
func (all *allCreator) isProvidingAllAddresses() bool {
	return all.adjustedVersion == IndeterminateIPVersion
}

func (all *allCreator) isSequential() bool {
	addr, _ := all.getProviderAddress()
	if addr != nil {
		return addr.IsSequential()
	}
	return false
}

func (all *allCreator) providerCompare(other ipAddressProvider) (int, address_error.IncompatibleAddressError) {
	return providerCompare(all, other)
}

func (all *allCreator) providerEquals(other ipAddressProvider) (bool, address_error.IncompatibleAddressError) {
	return providerEquals(all, other)
}

func (all *allCreator) getProviderNetworkPrefixLen() PrefixLen {
	return all.qualifier.getEquivalentPrefixLen()
}

func (all *allCreator) getProviderMask() *IPAddress {
	return all.qualifier.getMaskLower()
}

func (all *allCreator) versionedCreate(version IPVersion) (addr *IPAddress, address_Error address_error.IncompatibleAddressError) {
	if version == all.adjustedVersion {
		return all.getProviderAddress()
	} else if all.adjustedVersion != IndeterminateIPVersion {
		return nil, nil
	}
	addr, _, _, _, address_Error = createAllAddress(
		version,
		&all.qualifier,
		all.originator)
	return
}

func newMaskCreator(options address_string_param.IPAddressStringParams, adjustedVersion IPVersion, networkPrefixLength PrefixLen) *maskCreator {
	if adjustedVersion == IndeterminateIPVersion {
		adjustedVersion = IPVersion(options.GetPreferredVersion())
	}

	createVersionedMask := func(version IPVersion, prefLen PrefixLen, withPrefixLength bool) *IPAddress {
		if version == IPv4 {
			network := ipv4Network
			return network.GetNetworkMask(prefLen.bitCount())
		} else if version == IPv6 {
			network := ipv6Network
			return network.GetNetworkMask(prefLen.bitCount())
		}
		return nil
	}

	versionedAddressCreatorFunc := func(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
		return createVersionedMask(version, networkPrefixLength, true), nil
	}

	maskCreatorFunc := func() (address, hostAddress *IPAddress) {
		prefLen := networkPrefixLength
		return createVersionedMask(adjustedVersion, prefLen, true),
			createVersionedMask(adjustedVersion, prefLen, false)
	}

	addrCreator := func() (address, hostAddress *IPAddress, address_Error, hosterr address_error.IncompatibleAddressError) {
		address, hostAddress = maskCreatorFunc()
		return
	}

	cached := cachedAddressProvider{addressCreator: addrCreator}
	return &maskCreator{
		adjustedAddressCreator{
			networkPrefixLength: networkPrefixLength,
			versionedAddressCreator: versionedAddressCreator{
				adjustedVersion:             adjustedVersion,
				parameters:                  options,
				cachedAddressProvider:       cached,
				versionedAddressCreatorFunc: versionedAddressCreatorFunc,
			},
		},
	}
}

// Wraps an IPAddress for IPAddressString in the cases where no parsing is provided, the address exists already
func getProviderFor(address, hostAddress *IPAddress) ipAddressProvider {
	return &cachedAddressProvider{addresses: &addressResult{address: address, hostAddress: hostAddress}}
}

func emptyAddressCreator(emptyStrOption address_string_param.EmptyStrOption, version IPVersion, zone Zone) (addrCreator func() (address, hostAddress *IPAddress), versionedCreator func() *IPAddress) {
	preferIPv6 := version.IsIPv6()
	double := func(one *IPAddress) (address, hostAddress *IPAddress) {
		return one, one
	}

	if emptyStrOption == address_string_param.NoAddressOption {
		addrCreator = func() (*IPAddress, *IPAddress) { return double(nil) }
		versionedCreator = func() *IPAddress { return nil }
	} else if emptyStrOption == address_string_param.LoopbackOption {
		if preferIPv6 {
			if len(zone) > 0 {
				ipv6WithZoneLoop := func() *IPAddress {
					network := ipv6Network
					creator := network.getIPAddressCreator()
					return creator.createAddressInternalFromBytes(network.GetLoopback().Bytes(), zone)
				}
				versionedCreator = ipv6WithZoneLoop
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6WithZoneLoop()) }
			} else {
				ipv6Loop := func() *IPAddress {
					return ipv6Network.GetLoopback()
				}
				versionedCreator = ipv6Loop
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6Loop()) }
			}
		} else {
			ipv4Loop := func() *IPAddress {
				return ipv4Network.GetLoopback()
			}
			addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv4Loop()) }
			versionedCreator = ipv4Loop
		}
	} else { // EmptyStrParsedAs() == ZeroAddressOption
		if preferIPv6 {
			if len(zone) > 0 {
				ipv6WithZoneZero := func() *IPAddress {
					network := ipv6Network
					creator := network.getIPAddressCreator()
					return creator.createAddressInternalFromBytes(zeroIPv6.Bytes(), zone)
				}
				versionedCreator = ipv6WithZoneZero
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6WithZoneZero()) }
			} else {
				ipv6Zero := func() *IPAddress {
					return zeroIPv6.ToIP()
				}
				versionedCreator = ipv6Zero
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6Zero()) }
			}
		} else {
			ipv4Zero := func() *IPAddress {
				return zeroIPv4.ToIP()
			}
			addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv4Zero()) }
			versionedCreator = ipv4Zero
		}
	}
	return
}

func newEmptyAddrCreator(options address_string_param.IPAddressStringParams, zone Zone) *emptyAddrCreator {
	var version = IPVersion(options.GetPreferredVersion())
	// EmptyStrParsedAs chooses whether to produce loopbacks, zero addresses, or nothing for the empty string ""
	addrCreator, versionedCreator := emptyAddressCreator(options.EmptyStrParsedAs(), version, zone)
	cached := cachedAddressProvider{
		addressCreator: func() (address, hostAddress *IPAddress, address_Error, hosterr address_error.IncompatibleAddressError) {
			address, hostAddress = addrCreator()
			return
		},
	}
	versionedCreatorFunc := func(v IPVersion) *IPAddress {
		addresses := cached.addresses
		if addresses != nil {
			addr := addresses.address
			if v == addr.GetIPVersion() {
				return addr
			}
		}
		if v.IsIndeterminate() {
			return versionedCreator()
		}
		_, vCreator := emptyAddressCreator(options.EmptyStrParsedAs(), v, zone)
		return vCreator()
	}
	versionedAddressCreatorFunc := func(version IPVersion) (*IPAddress, address_error.IncompatibleAddressError) {
		return versionedCreatorFunc(version), nil
	}
	return &emptyAddrCreator{
		versionedAddressCreator: versionedAddressCreator{
			adjustedVersion:             version,
			parameters:                  options,
			cachedAddressProvider:       cached,
			versionedAddressCreatorFunc: versionedAddressCreatorFunc,
		},
		zone: zone,
	}
}
