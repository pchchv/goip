package address_string_param

var (
	_                RangeParams = &rangeParameters{}
	WildcardAndRange RangeParams = &rangeParameters{} // use this to support addresses supported by the default wildcard options and also addresses like "1.2-3.3.4" or "1:0-ff::".
	NoRange          RangeParams = &rangeParameters{  // use no wildcards nor range separators
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
