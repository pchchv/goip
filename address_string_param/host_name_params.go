package address_string_param

// hostNameParameters has parameters for parsing host name strings.
// They are immutable and can be constructed using an HostNameParamsBuilder.
type hostNameParameters struct {
	ipParams           ipAddressStringParameters
	preferredVersion   IPVersion
	noNormalizeToLower bool
	noBracketedIPv4    bool
	noBracketedIPv6    bool
	noIPAddress        bool
	expectPort         bool
	noService          bool
	noEmpty            bool
	noPort             bool
}

// AllowsEmpty determines if an empty host string is considered valid.
// The parser will first parse as an empty address, if allowed by the nested IPAddressStringParams.
// Otherwise, it will be considered an empty host if this returns true, or an invalid host if it returns false.
func (params *hostNameParameters) AllowsEmpty() bool {
	return !params.noEmpty
}

// GetPreferredVersion indicates the version to prefer when resolving host names.
func (params *hostNameParameters) GetPreferredVersion() IPVersion {
	return params.preferredVersion
}

// AllowsBracketedIPv4 allows bracketed IPv4 addresses like "[1.2.3.4]".
func (params *hostNameParameters) AllowsBracketedIPv4() bool {
	return !params.noBracketedIPv4
}

// AllowsBracketedIPv6 allows bracketed IPv6 addresses like "[1::2]".
func (params *hostNameParameters) AllowsBracketedIPv6() bool {
	return !params.noBracketedIPv6
}

// NormalizesToLowercase indicates whether to normalize the host name to lowercase characters when parsing.
func (params *hostNameParameters) NormalizesToLowercase() bool {
	return !params.noNormalizeToLower
}

// AllowsIPAddress allows a host name to specify an IP address or subnet.
func (params *hostNameParameters) AllowsIPAddress() bool {
	return !params.noIPAddress
}

// AllowsPort allows a host name to specify a port.
func (params *hostNameParameters) AllowsPort() bool {
	return !params.noPort
}

// AllowsService allows a host name to specify a service, which typically maps to a port.
func (params *hostNameParameters) AllowsService() bool {
	return !params.noService
}

// ExpectsPort indicates whether a port should be inferred from a host like 1:2:3:4::80
// that is ambiguous if a port might have been appended.
// The final segment would normally be considered part of the address,
// but can be interpreted as a port instead.
func (params *hostNameParameters) ExpectsPort() bool {
	return params.expectPort
}

// GetIPAddressParams returns the parameters that apply specifically to IP addresses and subnets, whenever a host name specifies an IP addresses or subnet.
func (params *hostNameParameters) GetIPAddressParams() IPAddressStringParams {
	return &params.ipParams
}
