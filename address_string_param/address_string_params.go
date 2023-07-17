package address_string_param

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
