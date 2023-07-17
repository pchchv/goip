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
