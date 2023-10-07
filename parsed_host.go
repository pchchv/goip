package goip

import (
	"strings"

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

func (host *parsedHost) buildNormalizedLabels() []string {
	if host.parsedHostCache == nil {
		var normalizedLabels []string
		if host.hasEmbeddedAddress() {
			addressProvider := host.getAddressProvider()
			addr, err := addressProvider.getProviderAddress()
			if err == nil && addr != nil {
				section := addr.GetSection()
				normalizedLabels = section.GetSegmentStrings()
			} else {
				hostStr := host.mapString(addressProvider)
				if addressProvider.isProvidingEmpty() {
					normalizedLabels = []string{}
				} else {
					normalizedLabels = []string{hostStr}
				}
			}
		} else {
			normalizedLabels = make([]string, len(host.separatorIndices))
			normalizedFlags := host.normalizedFlags

			for i, lastSep := 0, -1; i < len(normalizedLabels); i++ {
				index := host.separatorIndices[i]
				if len(normalizedFlags) > 0 && !normalizedFlags[i] {
					var normalizedLabelBuilder strings.Builder
					normalizedLabelBuilder.Grow((index - lastSep) - 1)
					for j := lastSep + 1; j < index; j++ {
						c := host.originalStr[j]
						if c >= 'A' && c <= 'Z' {
							c = c + ('a' - 'A')
						}
						normalizedLabelBuilder.WriteByte(c)
					}
					normalizedLabels[i] = normalizedLabelBuilder.String()
				} else {
					normalizedLabels[i] = host.originalStr[lastSep+1 : index]
				}
				lastSep = index
			}
		}
		return normalizedLabels
	}
	return host.parsedHostCache.normalizedLabels
}
