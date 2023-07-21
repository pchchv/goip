package address_string_param

var (
	_                AddressStringFormatParams = &addressStringFormatParameters{}
	_                AddressStringParams       = &addressStringParameters{}
	_                RangeParams               = &rangeParameters{}
	WildcardAndRange RangeParams               = &rangeParameters{} // use this to support addresses supported by the default wildcard options and also addresses like "1.2-3.3.4" or "1:0-ff::".
	NoRange          RangeParams               = &rangeParameters{  // use no wildcards nor range separators
		noWildcard:         true,
		noValueRange:       true,
		noReverseRange:     true,
		noSingleWildcard:   true,
		noInferredBoundary: true,
	}
	WildcardOnly RangeParams = &rangeParameters{ // use this to support addresses like "1.*.3.4" or "1::*:3" or "1.2_.3.4" or "1::a__:3"
		noValueRange:   true,
		noReverseRange: true,
	}
)

// RangeParams indicates what wildcards and ranges are allowed in the string.
type RangeParams interface {
	// AllowsWildcard indicates whether '*' is allowed to denote segments covering all possible segment values
	AllowsWildcard() bool
	// AllowsRangeSeparator indicates whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
	AllowsRangeSeparator() bool
	// AllowsSingleWildcard indicates whether to allow a segment terminating with '_' characters, which represent any digit
	AllowsSingleWildcard() bool
	// AllowsReverseRange indicates whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
	AllowsReverseRange() bool
	// AllowsInferredBoundary indicates whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
	AllowsInferredBoundary() bool
}

type AddressStringFormatParams interface {
	// AllowsWildcardedSeparator controls whether the wildcard '*' or '%' can replace the segment separators '.' and ':'.
	// If so, then you can write addresses like "*.*" or "*:*".
	AllowsWildcardedSeparator() bool
	// AllowsLeadingZeros indicates whether you allow addresses with segments that have leasing zeros like "001.2.3.004" or "1:000a::".
	// For IPV4, this option overrides inet_aton octal.
	// Single segment addresses that must have the requisite length to be parsed are not affected by this flag.
	AllowsLeadingZeros() bool
	// AllowsUnlimitedLeadingZeros determines if you allow leading zeros that extend segments
	// beyond the usual segment length, which is 3 for IPv4 dotted-decimal and 4 for IPv6.
	// However, this only takes effect if leading zeros are allowed, which is when
	// AllowsLeadingZeros is true or the address is IPv4 and Allows_inet_aton_octal is true.
	// For example, this determines whether you allow "0001.0002.0003.0004".
	AllowsUnlimitedLeadingZeros() bool
	// GetRangeParams returns the RangeParams describing whether ranges of values are allowed and what wildcards are allowed.
	GetRangeParams() RangeParams
}

type AddressStringParams interface {
	// AllowsEmpty indicates whether it allows zero-length address strings: ""
	AllowsEmpty() bool
	// AllowsSingleSegment allows the address to be specified as a single value, such as ffffffff,
	// without the standard use of segments like "1.2.3.4" or "1:2:4:3:5:6:7:8".
	AllowsSingleSegment() bool
	// AllowsAll indicates whether we allow a string of just the wildcard "*" to represent all addresses of any version.
	// If false, for IP addresses check the preferred version with GetPreferredVersion() and
	// then check AllowsWildcardedSeparator to determine if the string represents all addresses of that version.
	AllowsAll() bool
}

type rangeParameters struct {
	noWildcard, noValueRange, noReverseRange, noSingleWildcard, noInferredBoundary bool
}

// AllowsWildcard indicates whether '*' is allowed to denote segments covering all possible segment values.
func (builder *rangeParameters) AllowsWildcard() bool {
	return !builder.noWildcard
}

// AllowsRangeSeparator indicates whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10.
func (builder *rangeParameters) AllowsRangeSeparator() bool {
	return !builder.noValueRange
}

// AllowsReverseRange indicates whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1.
func (builder *rangeParameters) AllowsReverseRange() bool {
	return !builder.noReverseRange
}

// AllowsInferredBoundary indicates whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value.
func (builder *rangeParameters) AllowsInferredBoundary() bool {
	return !builder.noInferredBoundary
}

// AllowsSingleWildcard indicates whether to allow a segment terminating with '_' characters, which represent any digit.
func (builder *rangeParameters) AllowsSingleWildcard() bool {
	return !builder.noSingleWildcard
}

// RangeParamsBuilder is used to build an immutable RangeParams for parsing address strings.
type RangeParamsBuilder struct {
	rangeParameters
	parent interface{}
}

// ToParams returns an immutable RangeParams instance built by this builder.
func (builder *RangeParamsBuilder) ToParams() RangeParams {
	return &builder.rangeParameters
}

// Set initializes builder with the values from the given RangeParams.
func (builder *RangeParamsBuilder) Set(rangeParams RangeParams) *RangeParamsBuilder {
	if rp, ok := rangeParams.(*rangeParameters); ok {
		builder.rangeParameters = *rp
	} else {
		builder.rangeParameters = rangeParameters{
			noWildcard:         !rangeParams.AllowsWildcard(),
			noValueRange:       !rangeParams.AllowsRangeSeparator(),
			noReverseRange:     !rangeParams.AllowsReverseRange(),
			noSingleWildcard:   !rangeParams.AllowsSingleWildcard(),
			noInferredBoundary: !rangeParams.AllowsInferredBoundary(),
		}
	}
	return builder
}

// AllowWildcard dictates whether '*' is allowed to denote segments covering all possible segment values.
func (builder *RangeParamsBuilder) AllowWildcard(allow bool) *RangeParamsBuilder {
	builder.noWildcard = !allow
	return builder
}

// AllowRangeSeparator specifies whether '-'
// (or the expected range separator for an address)
// is allowed to indicate a range from smaller to larger, such as 1-10.
func (builder *RangeParamsBuilder) AllowRangeSeparator(allow bool) *RangeParamsBuilder {
	builder.noValueRange = !allow
	return builder
}

// AllowReverseRange specifies whether '-'
// (or the expected range separator for an address)
// is allowed to be used to indicate a range from larger to smaller, such as 10-1.
func (builder *RangeParamsBuilder) AllowReverseRange(allow bool) *RangeParamsBuilder {
	builder.noReverseRange = !allow
	return builder
}

// AllowInferredBoundary determines whether it is allowed to designate a missing range value before or
// after the '-' sign to indicate a minimum or maximum potential value.
func (builder *RangeParamsBuilder) AllowInferredBoundary(allow bool) *RangeParamsBuilder {
	builder.noInferredBoundary = !allow
	return builder
}

// AllowSingleWildcard determines whether to allow a segment ending with '_' characters that represent any digit.
func (builder *RangeParamsBuilder) AllowSingleWildcard(allow bool) *RangeParamsBuilder {
	builder.noSingleWildcard = !allow
	return builder
}

// addressStringFormatParams are parameters specific to a given address type or version that is supplied.
type addressStringFormatParameters struct {
	rangeParams             rangeParameters
	noWildcardedSeparator   bool
	noLeadingZeros          bool
	noUnlimitedLeadingZeros bool
}

// AllowsWildcardedSeparator controls whether the wildcard '*' or '%' can replace the segment delimiters '.' and ':'.
// If so, addresses like *.* or *:* can be written.
func (params *addressStringFormatParameters) AllowsWildcardedSeparator() bool {
	return !params.noWildcardedSeparator
}

// AllowsLeadingZeros indicates whether to allow addresses with segments containing leading zeros, such as "001.2.3.004" or "1:000a::".
// For IPV4, this option overrides inet_aton octal.
// Single-segment addresses, which must have the required length for parsing, are not affected by this flag.
func (params *addressStringFormatParameters) AllowsLeadingZeros() bool {
	return !params.noLeadingZeros
}

// AllowsUnlimitedLeadingZeros determines whether to allow leading zeros that
// extend segments beyond the usual segment length of 3 for IPv4 dotted-decimal and 4 for IPv6.
// However, this parameter is valid only if leading zeros are allowed, that is,
// when AllowsLeadingZeros is true or the address is IPv4 and Allows_inet_aton_octal is true.
// For example, this determines whether to allow "0001.0002.0003.0004".
func (params *addressStringFormatParameters) AllowsUnlimitedLeadingZeros() bool {
	return !params.noUnlimitedLeadingZeros
}

// GetRangeParams returns RangeParams parameters describing whether ranges of values are allowed and what wildcards are allowed.
func (params *addressStringFormatParameters) GetRangeParams() RangeParams {
	return &params.rangeParams
}

type addressStringParameters struct {
	noEmpty, noAll, noSingleSegment bool
}

// AllowsEmpty indicates whether it allows zero-length address strings: "".
func (params *addressStringParameters) AllowsEmpty() bool {
	return !params.noEmpty
}

// AllowsSingleSegment allows an address to be specified as a single value, eg ffffffff, without the standard use of segments like "1.2.3.4" or "1:2:4:3:5:6:7:8".
func (params *addressStringParameters) AllowsSingleSegment() bool {
	return !params.noSingleSegment
}

// AllowsAll indicates if we allow the string of just the wildcard "*" to denote all addresses of all version.
// If false, then for IP addresses we check the preferred version with GetPreferredVersion(), and then check AllowsWildcardedSeparator(),
// to determine if the string represents all addresses of that version.
func (params *addressStringParameters) AllowsAll() bool {
	return !params.noAll
}

// AddressStringParamsBuilder builds an AddressStringParams.
type AddressStringParamsBuilder struct {
	addressStringParameters
}

func (builder *AddressStringParamsBuilder) set(params AddressStringParams) {
	if p, ok := params.(*addressStringParameters); ok {
		builder.addressStringParameters = *p
	} else {
		builder.addressStringParameters = addressStringParameters{
			noEmpty:         !params.AllowsEmpty(),
			noAll:           !params.AllowsAll(),
			noSingleSegment: !params.AllowsSingleSegment(),
		}
	}
}

// ToParams returns an immutable AddressStringParams instance built by this builder.
func (builder *AddressStringParamsBuilder) ToParams() AddressStringParams {
	return &builder.addressStringParameters
}

func (builder *AddressStringParamsBuilder) allowEmpty(allow bool) {
	builder.noEmpty = !allow
}

func (builder *AddressStringParamsBuilder) allowAll(allow bool) {
	builder.noAll = !allow
}

func (builder *AddressStringParamsBuilder) allowSingleSegment(allow bool) {
	builder.noSingleSegment = !allow
}

// AddressStringFormatParamsBuilder creates parameters for parsing a specific address type or address version.
type AddressStringFormatParamsBuilder struct {
	addressStringFormatParameters
	rangeParamsBuilder RangeParamsBuilder
}

// ToParams returns an immutable AddressStringFormatParams instance built by this builder.
func (builder *AddressStringFormatParamsBuilder) ToParams() AddressStringFormatParams {
	result := &builder.addressStringFormatParameters
	result.rangeParams = *builder.rangeParamsBuilder.ToParams().(*rangeParameters)
	return result
}

func (builder *AddressStringFormatParamsBuilder) set(parms AddressStringFormatParams) {
	if p, ok := parms.(*addressStringFormatParameters); ok {
		builder.addressStringFormatParameters = *p
	} else {
		builder.addressStringFormatParameters = addressStringFormatParameters{
			noWildcardedSeparator:   !parms.AllowsWildcardedSeparator(),
			noLeadingZeros:          !parms.AllowsLeadingZeros(),
			noUnlimitedLeadingZeros: !parms.AllowsUnlimitedLeadingZeros(),
		}
	}
	builder.rangeParamsBuilder.Set(parms.GetRangeParams())
}
