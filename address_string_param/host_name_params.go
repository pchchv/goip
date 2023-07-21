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
