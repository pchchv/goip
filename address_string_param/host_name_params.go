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
