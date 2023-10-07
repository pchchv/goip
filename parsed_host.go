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
