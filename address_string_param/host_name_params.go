package address_string_param

// HostNameParams provides parameters for parsing host name strings.
// This allows the validation performed by HostName to be checked.
// HostName uses a default permissive HostNameParams object when one is not specified.
// If you want to use parameters other than the defaults, use this interface.
// Immutable instances can be constructed with HostNameParamsBuilder.
type HostNameParams interface {
	// AllowsEmpty determines whether an empty host string is considered valid.
	// If the nested IPAddressStringParams parameters allow it, the empty address will be parsed first.
	// Otherwise, it will be considered an empty host if this value returns true, or an invalid host if it returns false.
	AllowsEmpty() bool
	// GetPreferredVersion indicates the version to prefer when resolving host names.
	GetPreferredVersion() IPVersion
	// AllowsBracketedIPv4 allows bracketed IPv4 addresses like "[1.2.3.4]".
	AllowsBracketedIPv4() bool
	// AllowsBracketedIPv6 allows bracketed IPv6 addresses like "[1::2]".
	AllowsBracketedIPv6() bool
	// NormalizesToLowercase indicates whether to normalize the host name to lowercase characters when parsing.
	NormalizesToLowercase() bool
	// AllowsIPAddress allows a host name to specify an IP address or subnet.
	AllowsIPAddress() bool
	// AllowsPort allows a host name to specify a port.
	AllowsPort() bool
	// AllowsService allows a host name to specify a service, which typically maps to a port.
	AllowsService() bool
	// ExpectsPort indicates whether a port should be inferred from a host like 1:2:3:4::80 that is ambiguous if a port might have been appended.
	// The final segment would normally be considered part of the address, but can be interpreted as a port instead.
	ExpectsPort() bool
	// GetIPAddressParams returns the parameters that apply specifically to IP addresses and subnets, whenever a host name specifies an IP addresses or subnet.
	GetIPAddressParams() IPAddressStringParams
}

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

// HostNameParamsBuilder builds an immutable HostNameParams for controlling parsing of host names.
type HostNameParamsBuilder struct {
	hostNameParameters
	ipAddressBuilder IPAddressStringParamsBuilder
}

// ToParams returns an immutable HostNameParams instance built by this builder.
func (builder *HostNameParamsBuilder) ToParams() HostNameParams {
	// We don't return a pointer to builder.hostNameParameters,
	// because that would allow us to change the parameters while still using the same builder,
	// and we need immutable objects for concurrency safety, so we can't allow it.
	result := builder.hostNameParameters
	result.ipParams = *builder.ipAddressBuilder.ToParams().(*ipAddressStringParameters)
	return &result
}

// GetIPAddressParamsBuilder returns a builder that builds
// the IPAddressStringParams for the HostNameParams being built by this builder.
func (builder *HostNameParamsBuilder) GetIPAddressParamsBuilder() (result *IPAddressStringParamsBuilder) {
	result = &builder.ipAddressBuilder
	result.parent = builder
	return
}

// SetIPAddressParams populates this builder with the values from the given IPAddressStringParams.
func (builder *HostNameParamsBuilder) SetIPAddressParams(params IPAddressStringParams) *HostNameParamsBuilder {
	builder.ipAddressBuilder.Set(params)
	return builder
}

// Set populates this builder with the values from the given HostNameParams.
func (builder *HostNameParamsBuilder) Set(params HostNameParams) *HostNameParamsBuilder {
	if p, ok := params.(*hostNameParameters); ok {
		builder.hostNameParameters = *p
	} else {
		builder.hostNameParameters = hostNameParameters{
			preferredVersion:   params.GetPreferredVersion(),
			noEmpty:            !params.AllowsEmpty(),
			noBracketedIPv4:    !params.AllowsBracketedIPv4(),
			noBracketedIPv6:    !params.AllowsBracketedIPv6(),
			noNormalizeToLower: !params.NormalizesToLowercase(),
			noIPAddress:        !params.AllowsIPAddress(),
			noPort:             !params.AllowsPort(),
			noService:          !params.AllowsService(),
			expectPort:         params.ExpectsPort(),
		}
	}
	return builder.SetIPAddressParams(params.GetIPAddressParams())
}

// AllowEmpty dictates whether an empty host string is considered valid.
// The parser will first parse as an empty address, if allowed by the nested IPAddressStringParams.
// Otherwise, this setting dictates whether it will be considered an invalid host.
func (builder *HostNameParamsBuilder) AllowEmpty(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noEmpty = !allow
	return builder
}

// SetPreferredVersion dictates the version to prefer when resolving host names.
func (builder *HostNameParamsBuilder) SetPreferredVersion(version IPVersion) *HostNameParamsBuilder {
	builder.hostNameParameters.preferredVersion = version
	return builder
}

// AllowBracketedIPv4 dictates whether to allow bracketed IPv4 addresses like "[1.2.3.4]".
func (builder *HostNameParamsBuilder) AllowBracketedIPv4(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noBracketedIPv4 = !allow
	return builder
}

// AllowBracketedIPv6 dictates whether to allow bracketed IPv6 addresses like "[1::2]".
func (builder *HostNameParamsBuilder) AllowBracketedIPv6(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noBracketedIPv6 = !allow
	return builder
}
