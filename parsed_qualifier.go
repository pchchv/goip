package goip

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
