package address_string_param

const (
	MAC48Len          MACAddressLen = "MAC48" // indicates 48-bit MAC addresses
	EUI64Len          MACAddressLen = "EUI64" // indicates 64-bit MAC addresses
	UnspecifiedMACLen MACAddressLen = ""      // indicates unspecified bit-length MAC addresses
)

var (
	_ MACAddressStringParams       = &macAddressStringParameters{}
	_ MACAddressStringFormatParams = &macAddressStringFormatParameters{}
)

// MACAddressLen is an option indicating a MAC address length.
type MACAddressLen string

// MACAddressStringFormatParams provides format parameters for MAC addresses,
// indicating what formatting is allowed.
type MACAddressStringFormatParams interface {
	AddressStringFormatParams
	// AllowsShortSegments allows segments that are just a single hex digit and not two.
	AllowsShortSegments() bool
}

// MACAddressStringParams provides parameters for parsing MAC address strings.
// This allows you to control the validation performed by MACAddressString.
// MACAddressString uses the default MACAddressStringParams resolving instance if one is not specified.
// If you want to use parameters other than the default, use this interface.
// Immutable instances can be constructed using the MACAddressStringParamsBuilder.
type MACAddressStringParams interface {
	AddressStringParams
	// GetPreferredLen indicates whether an ambiguous address like * is considered to be MAC 6 bytes, EUI-64 8 bytes, or either one.
	GetPreferredLen() MACAddressLen
	// AllowsDashed allows addresses like "aa-bb-cc-dd-ee-ff".
	AllowsDashed() bool
	// AllowsSingleDashed allows addresses like "aabbcc-ddeeff".
	AllowsSingleDashed() bool
	// AllowsColonDelimited allows addresses like "aa:bb:cc:dd:ee:ff".
	AllowsColonDelimited() bool
	// AllowsDotted allows addresses like "aaa.bbb.ccc.ddd".
	AllowsDotted() bool
	// AllowsSpaceDelimited allows addresses like "aa bb cc dd ee ff".
	AllowsSpaceDelimited() bool
	// GetFormatParams returns the parameters that apply to formatting of the address segments.
	GetFormatParams() MACAddressStringFormatParams
}

type macAddressStringFormatParameters struct {
	addressStringFormatParameters
	noShortSegments bool
}

// AllowsShortSegments allows segments that are just a single hex digit and not two.
func (params *macAddressStringFormatParameters) AllowsShortSegments() bool {
	return !params.noShortSegments
}

// macAddressStringParameters has parameters for parsing MAC address strings.
// They are immutable and must be constructed using an IPAddressStringParamsBuilder.
type macAddressStringParameters struct {
	addressStringParameters
	formatParams          macAddressStringFormatParameters
	noAllowDashed         bool
	noAllowSingleDashed   bool
	noAllowColonDelimited bool
	noAllowDotted         bool
	noAllowSpaceDelimited bool
	allAddresses          MACAddressLen
}

// GetPreferredLen indicates whether an ambiguous address like * is considered to be MAC 6 bytes, EUI-64 8 bytes, or either one.
func (params *macAddressStringParameters) GetPreferredLen() MACAddressLen {
	return params.allAddresses
}

// AllowsDashed allows addresses like "aa-bb-cc-dd-ee-ff".
func (params *macAddressStringParameters) AllowsDashed() bool {
	return !params.noAllowDashed
}

// AllowsSingleDashed allows addresses like "aabbcc-ddeeff".
func (params *macAddressStringParameters) AllowsSingleDashed() bool {
	return !params.noAllowSingleDashed
}

// AllowsColonDelimited allows addresses like "aa:bb:cc:dd:ee:ff".
func (params *macAddressStringParameters) AllowsColonDelimited() bool {
	return !params.noAllowColonDelimited
}

// AllowsDotted allows addresses like "aaa.bbb.ccc.ddd".
func (params *macAddressStringParameters) AllowsDotted() bool {
	return !params.noAllowDotted
}

// AllowsSpaceDelimited allows addresses like "aa bb cc dd ee ff".
func (params *macAddressStringParameters) AllowsSpaceDelimited() bool {
	return !params.noAllowSpaceDelimited
}

// GetFormatParams returns the parameters that apply to formatting of the address segments.
func (params *macAddressStringParameters) GetFormatParams() MACAddressStringFormatParams {
	return &params.formatParams
}

// MACAddressStringParamsBuilder builds an immutable MACAddressStringParameters for controlling parsing of MAC address strings.
type MACAddressStringParamsBuilder struct {
	params macAddressStringParameters
	AddressStringParamsBuilder
	formatBuilder MACAddressStringFormatParamsBuilder
}

// ToParams returns an immutable MACAddressStringParams instance built by this builder.
func (builder *MACAddressStringParamsBuilder) ToParams() MACAddressStringParams {
	// do not return a pointer to builder.params because
	// that would allow macAddressStringParameters to be changed
	// while still using the same builder,
	// and we need immutable objects for concurrency safety,
	// so we can't allow that
	result := builder.params
	result.addressStringParameters = *builder.AddressStringParamsBuilder.ToParams().(*addressStringParameters)
	result.formatParams = *builder.formatBuilder.ToParams().(*macAddressStringFormatParameters)
	return &result
}

// Set populates this builder with the values from the given MACAddressStringParams.
func (builder *MACAddressStringParamsBuilder) Set(params MACAddressStringParams) *MACAddressStringParamsBuilder {
	if p, ok := params.(*macAddressStringParameters); ok {
		builder.params = *p
	} else {
		builder.params = macAddressStringParameters{
			noAllowDashed:         !params.AllowsDashed(),
			noAllowSingleDashed:   !params.AllowsSingleDashed(),
			noAllowColonDelimited: !params.AllowsColonDelimited(),
			noAllowDotted:         !params.AllowsDotted(),
			noAllowSpaceDelimited: !params.AllowsSpaceDelimited(),
			allAddresses:          params.GetPreferredLen(),
		}
	}
	builder.AddressStringParamsBuilder.set(params)
	builder.formatBuilder.Set(params.GetFormatParams())
	return builder
}

// GetFormatParamsBuilder returns a builder that builds the MACAddressStringFormatParams for the MACAddressStringParams being built by this builder.
func (builder *MACAddressStringParamsBuilder) GetFormatParamsBuilder() (result *MACAddressStringFormatParamsBuilder) {
	result = &builder.formatBuilder
	result.parent = builder
	return
}

// AllowEmpty dictates whether to allow empty zero-length address strings.
func (builder *MACAddressStringParamsBuilder) AllowEmpty(allow bool) *MACAddressStringParamsBuilder {
	builder.allowEmpty(allow)
	return builder
}

// AllowSingleSegment dictates whether to allow an address to be specified as a single value,
// eg "ffffffff", without the standard use of segments like "1.2.3.4" or "1:2:4:3:5:6:7:8".
func (builder *MACAddressStringParamsBuilder) AllowSingleSegment(allow bool) *MACAddressStringParamsBuilder {
	builder.allowSingleSegment(allow)
	return builder
}

// AllowAll dictates whether to allow the string of just the wildcard "*" to denote all MAC addresses.
func (builder *MACAddressStringParamsBuilder) AllowAll(allow bool) *MACAddressStringParamsBuilder {
	builder.allowAll(allow)
	return builder
}

// SetPreferredLen indicates the length for an ambiguous address like *,
// whether it is considered to be MAC 6 bytes, EUI-64 8 bytes, or either one.
func (builder *MACAddressStringParamsBuilder) SetPreferredLen(size MACAddressLen) *MACAddressStringParamsBuilder {
	builder.params.allAddresses = size
	return builder
}

// AllowDashed dictates whether to allow addresses like "aa-bb-cc-dd-ee-ff".
func (builder *MACAddressStringParamsBuilder) AllowDashed(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowDashed = !allow
	return builder
}

// AllowSingleDashed dictates whether to allow addresses like "aabbcc-ddeeff".
func (builder *MACAddressStringParamsBuilder) AllowSingleDashed(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowSingleDashed = !allow
	return builder
}

// AllowColonDelimited dictates whether to allow addresses like "aa:bb:cc:dd:ee:ff".
func (builder *MACAddressStringParamsBuilder) AllowColonDelimited(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowColonDelimited = !allow
	return builder
}

// AllowDotted dictates whether to allow addresses like "aaa.bbb.ccc.ddd".
func (builder *MACAddressStringParamsBuilder) AllowDotted(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowDotted = !allow
	return builder
}

// AllowSpaceDelimited dictates whether to allow addresses like "aa bb cc dd ee ff".
func (builder *MACAddressStringParamsBuilder) AllowSpaceDelimited(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowSpaceDelimited = !allow
	return builder
}

// AllowWildcardedSeparator dictates whether the wildcard '*' or '%' can replace the segment separators '.', '-' and ':'.
// If so, then you can write addresses like "*.*" or "*:*".
func (builder *MACAddressStringParamsBuilder) AllowWildcardedSeparator(allow bool) *MACAddressStringParamsBuilder {
	builder.GetFormatParamsBuilder().AllowWildcardedSeparator(allow)
	return builder
}

// SetRangeParams populates this builder with the values from the given RangeParams.
func (builder *MACAddressStringParamsBuilder) SetRangeParams(rangeParams RangeParams) *MACAddressStringParamsBuilder {
	builder.GetFormatParamsBuilder().SetRangeParams(rangeParams)
	return builder
}

// MACAddressStringFormatParamsBuilder builds an immutable MACAddressStringFormatParams for controlling parsing of MAC address strings.
type MACAddressStringFormatParamsBuilder struct {
	params macAddressStringFormatParameters
	AddressStringFormatParamsBuilder
	parent *MACAddressStringParamsBuilder
}

// Set populates this builder with the values from the given MACAddressStringFormatParams.
func (builder *MACAddressStringFormatParamsBuilder) Set(parms MACAddressStringFormatParams) *MACAddressStringFormatParamsBuilder {
	if p, ok := parms.(*macAddressStringFormatParameters); ok {
		builder.params = *p
	} else {
		builder.params = macAddressStringFormatParameters{
			noShortSegments: !parms.AllowsShortSegments(),
		}
	}
	builder.AddressStringFormatParamsBuilder.set(parms)
	return builder
}

// GetParentBuilder returns the original MACAddressStringParamsBuilder builder that this was obtained from,
// if this builder was obtained from a MACAddressStringParamsBuilder.
func (builder *MACAddressStringFormatParamsBuilder) GetParentBuilder() *MACAddressStringParamsBuilder {
	return builder.parent
}

// ToParams returns an immutable MACAddressStringFormatParams instance built by this builder.
func (builder *MACAddressStringFormatParamsBuilder) ToParams() MACAddressStringFormatParams {
	result := &builder.params
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

// GetRangeParamsBuilder returns a builder that builds the range parameters for these MAC address string format parameters.
func (builder *MACAddressStringFormatParamsBuilder) GetRangeParamsBuilder() *RangeParamsBuilder {
	result := &builder.rangeParamsBuilder
	result.parent = builder
	return result
}

// AllowWildcardedSeparator dictates whether the wildcard '*'
// or '%' can replace the segment separators '.', '-' and ':'.
// If so, then you can write addresses like "*.*" or "*:*".
func (builder *MACAddressStringFormatParamsBuilder) AllowWildcardedSeparator(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowWildcardedSeparator(allow)
	return builder
}

// AllowLeadingZeros dictates whether to allow addresses with segments that have leasing zeros like "01:02:03:04:05:06".
// Single segment addresses that must have the requisite length to be parsed are not affected by this flag.
func (builder *MACAddressStringFormatParamsBuilder) AllowLeadingZeros(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowLeadingZeros(allow)
	return builder
}

// AllowUnlimitedLeadingZeros dictates whether to allow leading zeros
// that extend segments beyond the usual segment length of 2 hex digits.
// However, this only takes effect if leading zeros are allowed,
// which is when AllowsLeadingZeros is true.
func (builder *MACAddressStringFormatParamsBuilder) AllowUnlimitedLeadingZeros(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

// SetRangeParams populates this builder with the values from the given RangeParams.
func (builder *MACAddressStringFormatParamsBuilder) SetRangeParams(rangeParams RangeParams) *MACAddressStringFormatParamsBuilder {
	builder.setRangeParameters(rangeParams)
	return builder
}

// AllowShortSegments dictates whether to allow segments that are just a single hex digit and not two.
func (builder *MACAddressStringFormatParamsBuilder) AllowShortSegments(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.params.noShortSegments = !allow
	return builder
}

// CopyMACAddressStringParams produces an immutable copy of the original MACAddressStringParams.
// Copying a MACAddressStringParams created by
// a MACAddressStringParamsBuilder is unnecessary since it is already immutable.
func CopyMACAddressStringParams(orig MACAddressStringParams) MACAddressStringParams {
	if p, ok := orig.(*macAddressStringParameters); ok {
		return p
	}
	return new(MACAddressStringParamsBuilder).Set(orig).ToParams()
}
