package goip

import "github.com/pchchv/goip/address_string_param"

type parsedHostIdentifierStringQualifier struct {
	// if there is a port for the host, this will be its numeric value
	port    Port   // non-nil for a host with port
	service string // non-empty for host with a service instead of a port
	// if there is a prefix length for the address, this will be its numeric value
	networkPrefixLength PrefixLen //non-nil for a prefix-only address, sometimes non-nil for IPv4, IPv6
	// If instead of a prefix length a mask was provided, this is the mask.
	// We can also have both a prefix length and mask if one is added when merging qualifiers  */'
	mask *parsedIPAddress
	// overrides the parsed mask if present
	mergedMask *IPAddress
	// this is the IPv6 scope id or network interface name
	zone    Zone
	isZoned bool
}

func (parsedQual *parsedHostIdentifierStringQualifier) clearPortOrService() {
	parsedQual.port = nil
	parsedQual.service = ""
}

func (parsedQual *parsedHostIdentifierStringQualifier) clearPrefixOrMask() {
	parsedQual.networkPrefixLength = nil
	parsedQual.mask = nil
}

func (parsedQual *parsedHostIdentifierStringQualifier) getNetworkPrefixLen() PrefixLen {
	return parsedQual.networkPrefixLength
}

// setZone distinguishes callers with empty zones vs callers in which there was no zone indicator
func (parsedQual *parsedHostIdentifierStringQualifier) setZone(zone *Zone) {
	if zone != nil {
		parsedQual.zone = *zone
		parsedQual.isZoned = true
	}
}

func (parsedQual *parsedHostIdentifierStringQualifier) getZone() Zone {
	return parsedQual.zone
}

func (parsedQual *parsedHostIdentifierStringQualifier) getPort() Port {
	return parsedQual.port
}

func (parsedQual *parsedHostIdentifierStringQualifier) getService() string {
	return parsedQual.service
}

func (parsedQual *parsedHostIdentifierStringQualifier) inferVersion(validationOptions address_string_param.IPAddressStringParams) IPVersion {
	if parsedQual.networkPrefixLength != nil {
		if parsedQual.networkPrefixLength.bitCount() > IPv4BitCount &&
			!validationOptions.GetIPv4Params().AllowsPrefixesBeyondAddressSize() {
			return IPv6
		}
	} else if mask := parsedQual.mask; mask != nil {
		if mask.isProvidingIPv6() {
			return IPv6
		} else if mask.isProvidingIPv4() {
			return IPv4
		}
	}

	if parsedQual.isZoned {
		return IPv6
	}

	return IndeterminateIPVersion
}

func (parsedQual *parsedHostIdentifierStringQualifier) getMaskLower() *IPAddress {
	if mask := parsedQual.mergedMask; mask != nil {
		return mask
	}

	if mask := parsedQual.mask; mask != nil {
		return mask.getValForMask()
	}

	return nil
}

func (parsedQual *parsedHostIdentifierStringQualifier) getEquivalentPrefixLen() PrefixLen {
	pref := parsedQual.getNetworkPrefixLen()
	if pref == nil {
		mask := parsedQual.getMaskLower()
		if mask != nil {
			pref = mask.GetBlockMaskPrefixLen(true)
		}
	}
	return pref
}
