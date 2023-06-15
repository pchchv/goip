// The address_string package provides interfaces to define how
// to create certain strings from addresses and address sections,
// as well as the builder types for creating instances of these interfaces.
//
// For example, StringOptionsBuilder creates instances that implement StringOptions to specify generic strings.
//
// For more specific versions and address types,
// there are more specific builders and corresponding interface types.
//
// Each instance created by the builder is immutable.
package address_string

// Wildcards determines the wildcards to use when constructing an address string.
// WildcardsBuilder can be used to create a Wildcards instance.
type Wildcards interface {
	// GetRangeSeparator returns the wildcard used to separate the lower and upper bound (inclusive) of a range of values.
	// If it is not specified, it defaults to RangeSeparatorStr, which is a hyphen '-'.
	GetRangeSeparator() string
	// GetWildcard returns the wildcard used to represent any legitimate value, which by default is an asterisk '*'.
	GetWildcard() string
	// GetSingleWildcard returns the wildcard used to represent any single digit, which by default is the underscore character '_'.
	GetSingleWildcard() string
}

type wildcards struct {
	rangeSeparator, wildcard, singleWildcard string //rangeSeparator cannot be empty, the other two can
}

// GetRangeSeparator returns the wildcard used to separate the lower and upper bound (inclusive) of a range of values.
// If it is not specified, it defaults to RangeSeparatorStr, which is a hyphen '-'.
func (wildcards *wildcards) GetRangeSeparator() string {
	return wildcards.rangeSeparator
}

// GetWildcard returns the wildcard used to represent any legitimate value, which by default is an asterisk '*'.
func (wildcards *wildcards) GetWildcard() string {
	return wildcards.wildcard
}

// GetSingleWildcard returns the wildcard used to represent any single digit, which by default is the underscore character '_'.
func (wildcards *wildcards) GetSingleWildcard() string {
	return wildcards.singleWildcard
}
