package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

var noQualifier = &parsedHostIdentifierStringQualifier{}

type parsedHostCache struct {
	normalizedLabels []string
	host             string
}

type embeddedAddress struct {
	isUNCIPv6Literal   bool
	isReverseDNS       bool
	addressStringError address_error.AddressStringError
	addressProvider    ipAddressProvider
}

type parsedHost struct {
	*parsedHostCache
	separatorIndices []int // can be nil
	normalizedFlags  []bool
	labelsQualifier  parsedHostIdentifierStringQualifier
	embeddedAddress  embeddedAddress
	originalStr      string
	params           address_string_param.HostNameParams
}

func (host *parsedHost) getAddressProvider() ipAddressProvider {
	return host.embeddedAddress.addressProvider
}

func (host *parsedHost) hasEmbeddedAddress() bool {
	return host.embeddedAddress.addressProvider != nil
}

func (host *parsedHost) getQualifier() *parsedHostIdentifierStringQualifier {
	return &host.labelsQualifier
}

func (host *parsedHost) isIPv6Address() bool {
	return host.hasEmbeddedAddress() && host.getAddressProvider().isProvidingIPv6()
}

func (host *parsedHost) getPort() Port {
	return host.labelsQualifier.getPort()
}

func (host *parsedHost) getService() string {
	return host.labelsQualifier.getService()
}

func (host *parsedHost) getNetworkPrefixLen() PrefixLen {
	return host.labelsQualifier.getNetworkPrefixLen()
}

func (host *parsedHost) getEquivalentPrefixLen() PrefixLen {
	return host.labelsQualifier.getEquivalentPrefixLen()
}

func (host *parsedHost) getMask() *IPAddress {
	return host.labelsQualifier.getMaskLower()
}

func (host *parsedHost) isAddressString() bool {
	return host.getAddressProvider() != nil
}

func (host *parsedHost) asAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	if host.hasEmbeddedAddress() {
		return host.getAddressProvider().getProviderAddress()
	}
	return nil, nil
}

func (host *parsedHost) mapString(addressProvider ipAddressProvider) string {
	if addressProvider.isProvidingAllAddresses() {
		return SegmentWildcardStr
	} else if addressProvider.isProvidingEmpty() {
		return ""
	}
	return host.originalStr
}
