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

const (
	ipv6SegmentSeparator     = ':'
	ipv6ZoneSeparatorStr     = "%"
	ipv4SegmentSeparator     = '.'
	macColonSegmentSeparator = ':'
	rangeSeparatorStr        = "-"
	segmentWildcardStr       = "*"
)

var (
	// DefaultWildcards is the default Wildcards instance, using '-' and '*' as range separator and wildcard.
	DefaultWildcards Wildcards     = &wildcards{rangeSeparator: rangeSeparatorStr, wildcard: segmentWildcardStr}
	_                StringOptions = &stringOptions{}
	falseVal                       = false
	trueVal                        = true
)

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

// WildcardsBuilder builds an instance of Wildcards.
type WildcardsBuilder struct {
	wildcards
}

// SetRangeSeparator sets the wildcard used to separate the lower and upper bound (inclusive) of a range of values.
// If not set, it defaults to RangeSeparatorStr, which is a hyphen '-'.
func (wildcards *WildcardsBuilder) SetRangeSeparator(str string) *WildcardsBuilder {
	wildcards.rangeSeparator = str
	return wildcards
}

// SetWildcard sets the wildcard used to represent any legitimate value, the default is an asterisk '*'.
func (wildcards *WildcardsBuilder) SetWildcard(str string) *WildcardsBuilder {
	wildcards.wildcard = str
	return wildcards
}

// SetSingleWildcard sets the wildcard used to represent any single digit, which by default is the underscore character '_'.
func (wildcards *WildcardsBuilder) SetSingleWildcard(str string) *WildcardsBuilder {
	wildcards.singleWildcard = str
	return wildcards
}

// ToWildcards returns an immutable Wildcards instance built by this builder.
func (wildcards *WildcardsBuilder) ToWildcards() Wildcards {
	res := wildcards.wildcards
	if res.rangeSeparator == "" {
		//rangeSeparator cannot be empty
		res.rangeSeparator = rangeSeparatorStr
	}
	return &res
}

// StringOptions represents a clear way to create a specific type of string.
type StringOptions interface {
	// GetWildcards returns wildcards specified for use in the string
	GetWildcards() Wildcards
	// IsReverse indicates whether the string segments should be printed in reverse from the usual order,
	// the usual order being most to least significant
	IsReverse() bool
	// IsUppercase specifies whether to use uppercase for hexadecimal or other radians with alphabetic characters
	IsUppercase() bool
	// IsExpandedSegments returns whether segments should be expanded to their maximum width, usually with leading zeros
	IsExpandedSegments() bool
	// GetRadix returns the radix used.
	// The default is hexadecimal, unless the IPv4 option builder is used, in which case decimal is the default
	GetRadix() int
	// GetSeparator returns a separator that separates address sections, usually ':' or '.'.  HasSeparator specifies whether to call this method.
	// By default, there is no separator unless the MAC, IPv6, or IPv4 option builder is used, in which case the separator is ':' for MAC and IPv6 and '.' for IPv4
	GetSeparator() byte
	// HasSeparator indicates whether there is a separator.
	// The default is false, with no separator, unless using the MAC, IPv6 or IPv4 option builder, in which case there is a separator by default
	HasSeparator() bool
	// GetAddressLabel returns a string to add to the entire address string, such as an octal, hexadecimal or binary prefix
	GetAddressLabel() string
	// GetSegmentStrPrefix returns a string prefix (if any) to add to each segment value, such as an octal, hexadecimal, or binary prefix
	GetSegmentStrPrefix() string
}

type stringOptions struct {
	wildcards Wildcards
	// default is hex
	base int
	// segment separator, and in the case of separated digits the default digit separator is ' ',
	// but usually it is either '.' or ':'
	separator byte
	segmentStrPrefix,
	addrLabel string
	expandSegments,
	reverse,
	uppercase bool
	// if not set, defaults to false, no delimiter
	hasSeparator *bool
}

// GetWildcards returns wildcards specified for use in the string.
func (opts *stringOptions) GetWildcards() Wildcards {
	return opts.wildcards
}

// IsReverse indicates whether the string segments should be printed in reverse from the usual order,
// the usual order being most to least significant.
func (opts *stringOptions) IsReverse() bool {
	return opts.reverse
}

// IsUppercase specifies whether to use uppercase for hexadecimal or other radians with alphabetic characters.
func (opts *stringOptions) IsUppercase() bool {
	return opts.uppercase
}

// IsExpandedSegments returns whether segments should be expanded to their maximum width, usually with leading zeros.
func (opts *stringOptions) IsExpandedSegments() bool {
	return opts.expandSegments
}

// GetRadix returns the radix used.
// The default is hexadecimal, unless the IPv4 option builder is used, in which case decimal is the default.
func (opts *stringOptions) GetRadix() int {
	return opts.base
}

// GetSeparator returns a separator that separates address sections, usually ':' or '.'.  HasSeparator specifies whether to call this method.
// By default, there is no separator unless the MAC, IPv6, or IPv4 option builder is used, in which case the separator is ':' for MAC and IPv6 and '.' for IPv4.
func (opts *stringOptions) GetSeparator() byte {
	return opts.separator
}

// HasSeparator indicates whether there is a separator.
// The default is false, with no separator, unless using the MAC, IPv6 or IPv4 option builder, in which case there is a separator by default.
func (opts *stringOptions) HasSeparator() bool {
	if opts.hasSeparator == nil {
		return false
	}
	return *opts.hasSeparator
}

// GetAddressLabel returns a string to add to the entire address string, such as an octal, hexadecimal or binary prefix.
func (opts *stringOptions) GetAddressLabel() string {
	return opts.addrLabel
}

// GetSegmentStrPrefix returns a string prefix (if any) to add to each segment value, such as an octal, hexadecimal, or binary prefix.
func (opts *stringOptions) GetSegmentStrPrefix() string {
	return opts.segmentStrPrefix
}

// StringOptionsBuilder is used to create an immutable StringOptions instance.
type StringOptionsBuilder struct {
	stringOptions
}
