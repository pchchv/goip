package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
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
