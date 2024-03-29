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
	// WildcardsNetworkOnly prints wildcards that are part of the network
	// (only possible when using subnet address notation, otherwise this option is ignored).
	WildcardsNetworkOnly WildcardOption = ""
	// WildcardsAll prints wildcards for any visible (uncompressed) segments.
	WildcardsAll WildcardOption = "allType"
	// ZerosCompression - compress the largest range of zero-segments.
	ZerosCompression CompressionChoiceOptions = "zeros"
	// HostPreferred - if there is a host section, compress the host along with any adjoining zero-segments, otherwise compress a range of zero-segments.
	HostPreferred CompressionChoiceOptions = "host preferred"
	// MixedPreferred - if there is a mixed section that is compressible according to the MixedCompressionOptions, compress the mixed section along with any adjoining zero-segments, otherwise compress a range of zero-segments.
	MixedPreferred CompressionChoiceOptions = "mixed preferred"
	// ZerosOrHost - compress the largest range of zero or host segments.
	ZerosOrHost CompressionChoiceOptions = ""
	// NoMixedCompression - do not allow compression of an IPv4 section.
	NoMixedCompression MixedCompressionOptions = "no mixed compression"
	// MixedCompressionNoHost - allow compression of the IPv4 section when there is no host of the prefixed address.
	MixedCompressionNoHost MixedCompressionOptions = "no host"
	// MixedCompressionCoveredByHost - compress the IPv4 section if it is part of the host of the prefixed address.
	MixedCompressionCoveredByHost MixedCompressionOptions = "covered by host"
	// AllowMixedCompression - allow compression of a the IPv4 section.
	AllowMixedCompression MixedCompressionOptions = ""
)

var (
	// DefaultWildcards is the default Wildcards instance, using '-' and '*' as range separator and wildcard.
	DefaultWildcards Wildcards         = &wildcards{rangeSeparator: rangeSeparatorStr, wildcard: segmentWildcardStr}
	_                StringOptions     = &stringOptions{}
	_                WildcardOptions   = &wildcardOptions{}
	_                IPStringOptions   = &ipStringOptions{}
	_                CompressOptions   = &compressOptions{}
	_                IPv6StringOptions = &ipv6StringOptions{}
	falseVal                           = false
	trueVal                            = true
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

// WildcardOption specifies parameters that specify when and where to use wildcards.
type WildcardOption string

// WildcardOptions specifies parameters that specify when and where to use wildcards, and which wildcards to use.
type WildcardOptions interface {
	GetWildcardOption() WildcardOption // returns the used WildcardOption parameter
	GetWildcards() Wildcards           // returns the wildcard characters to be used.
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
	base      int // default is hex
	// segment separator, and in the case of separated digits, the default digit separator is ' ',
	// but usually it is either '.' or ':'
	separator        byte
	segmentStrPrefix string
	addrLabel        string
	expandSegments   bool
	reverse          bool
	uppercase        bool
	hasSeparator     *bool // if not set, default is false, no separator
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

// SetWildcards defines wildcards to be used in the string.
func (builder *StringOptionsBuilder) SetWildcards(wildcards Wildcards) *StringOptionsBuilder {
	builder.wildcards = wildcards
	return builder
}

// SetReverse determines whether to print the line segments in reverse order from the normal order, with the normal order being the order from largest to smallest value.
func (builder *StringOptionsBuilder) SetReverse(reverse bool) *StringOptionsBuilder {
	builder.reverse = reverse
	return builder
}

// SetUppercase determines whether to use uppercase for hexadecimal or other alphabetic radians.
func (builder *StringOptionsBuilder) SetUppercase(uppercase bool) *StringOptionsBuilder {
	builder.uppercase = uppercase
	return builder
}

// SetExpandedSegments determines whether segments should be expanded to their maximum width, usually with leading zeros.
func (builder *StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *StringOptionsBuilder {
	builder.expandSegments = expandSegments
	return builder
}

// SetHasSeparator determines whether the separator is present.
// The default is false, with no separator, unless the MAC, IPv6 or IPv4 option builder is used, in which case the separator is present by default.
func (builder *StringOptionsBuilder) SetHasSeparator(has bool) *StringOptionsBuilder {
	if has {
		builder.hasSeparator = &trueVal
	} else {
		builder.hasSeparator = &falseVal
	}
	return builder
}

// SetSeparator defines a separator to separate address partitions, usually ':' or '.'.
// HasSeparator specifies whether this separator should be used or not.
func (builder *StringOptionsBuilder) SetSeparator(separator byte) *StringOptionsBuilder {
	builder.separator = separator
	builder.SetHasSeparator(true)
	return builder
}

// SetRadix sets the radix in use.
func (builder *StringOptionsBuilder) SetRadix(base int) *StringOptionsBuilder {
	builder.base = base
	return builder
}

// SetAddressLabel dictates a string to add to the entire address string, such as an octal, hexadecimal or binary prefix.
func (builder *StringOptionsBuilder) SetAddressLabel(label string) *StringOptionsBuilder {
	builder.addrLabel = label
	return builder
}

// SetSegmentStrPrefix dictates a string prefix to add to each segment value, such as an octal, hexadecimal, or binary prefix.
func (builder *StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *StringOptionsBuilder {
	builder.segmentStrPrefix = prefix
	return builder
}

// ToOptions returns an immutable StringOptions instance built by this constructor.
func (builder *StringOptionsBuilder) ToOptions() StringOptions {
	res := builder.stringOptions
	res.base, res.wildcards, res.separator = getDefaults(res.base, res.wildcards, res.separator)
	return &res
}

// MACStringOptionsBuilder creates an immutable StringOptions instance for MAC address strings.
type MACStringOptionsBuilder struct {
	StringOptionsBuilder
}

// SetWildcards defines wildcards to be used in the string.
func (builder *MACStringOptionsBuilder) SetWildcards(wildcards Wildcards) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

// SetReverse determines whether to print line segments in reverse order from the normal order, with the normal order being from largest to smallest value.
func (builder *MACStringOptionsBuilder) SetReverse(reverse bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetReverse(reverse)
	return builder
}

// SetUppercase determines whether to use uppercase for hexadecimal or other alphabetic radians.
func (builder *MACStringOptionsBuilder) SetUppercase(uppercase bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

// SetExpandedSegments determines whether segments should be expanded to their maximum width, usually with leading zeros.
func (builder *MACStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

// SetRadix sets the radix in use.
func (builder *MACStringOptionsBuilder) SetRadix(base int) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetRadix(base)
	return builder
}

// SetHasSeparator determines whether there is a separator.
// The default for MAC is true.
func (builder *MACStringOptionsBuilder) SetHasSeparator(has bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// SetSeparator specifies the separator for address partitions, for MAC the default is ':'.
// HasSeparator specifies whether to use this separator or not.
func (builder *MACStringOptionsBuilder) SetSeparator(separator byte) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSeparator(separator)
	return builder
}

// SetAddressLabel dictates a string to add to the entire address string, such as an octal, hexadecimal or binary prefix.
func (builder *MACStringOptionsBuilder) SetAddressLabel(label string) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetAddressLabel(label)
	return builder
}

// SetSegmentStrPrefix dictates a string prefix to add to each segment value, such as an octal, hexadecimal, or binary prefix.
func (builder *MACStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

// ToOptions returns an immutable StringOptions instance built by this constructor.
func (builder *MACStringOptionsBuilder) ToOptions() StringOptions {
	b := &builder.StringOptionsBuilder
	b.hasSeparator, b.separator = getMACDefaults(b.hasSeparator, b.separator)
	return builder.StringOptionsBuilder.ToOptions()
}

type wildcardOptions struct {
	wildcardOption WildcardOption
	wildcards      Wildcards
}

// GetWildcards returns the wildcards to be used.
func (opts *wildcardOptions) GetWildcards() Wildcards {
	return opts.wildcards
}

// GetWildcardOption returns the WildcardOption parameter used.
func (opts *wildcardOptions) GetWildcardOption() WildcardOption {
	return opts.wildcardOption
}

// IPStringOptions is an illustrative way to create a specific type of IP address or subnet string.
type IPStringOptions interface {
	StringOptions
	// GetAddressSuffix returns a suffix to be appended to the string.
	// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings.
	GetAddressSuffix() string
	// GetWildcardOption returns the WildcardOption to use.
	GetWildcardOption() WildcardOption
	// GetZoneSeparator specifies the separator that separates the zone from the address, the default is '%'.
	GetZoneSeparator() string
}

// WildcardOptionsBuilder is used to create an immutable WildcardOptions instance for address strings.
type WildcardOptionsBuilder struct {
	wildcardOptions
}

// SetWildcardOptions defines the WildcardOption to use.
func (builder *WildcardOptionsBuilder) SetWildcardOptions(wildcardOption WildcardOption) *WildcardOptionsBuilder {
	builder.wildcardOption = wildcardOption
	return builder
}

// SetWildcards dictates the wildcards to use.
func (builder *WildcardOptionsBuilder) SetWildcards(wildcards Wildcards) *WildcardOptionsBuilder {
	builder.wildcards = wildcards
	return builder
}

// ToOptions returns an immutable instance of WildcardOptions constructed by this constructor.
func (builder *WildcardOptionsBuilder) ToOptions() WildcardOptions {
	cpy := builder.wildcardOptions
	if builder.wildcards == nil {
		builder.wildcards = DefaultWildcards
	}
	return &cpy
}

type ipStringOptions struct {
	stringOptions
	addrSuffix     string
	wildcardOption WildcardOption // default is WildcardsNetworkOnly
	zoneSeparator  string         // default is IPv6ZoneSeparator
}

// GetAddressSuffix returns a suffix to be appended to the string.
// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings.
func (opts *ipStringOptions) GetAddressSuffix() string {
	return opts.addrSuffix
}

// GetWildcardOptions returns the WildcardOptions to use.
func (opts *ipStringOptions) GetWildcardOptions() WildcardOptions {
	options := &wildcardOptions{
		opts.wildcardOption,
		opts.GetWildcards(),
	}
	return options
}

// GetWildcardOption returns the WildcardOption to use.
func (opts *ipStringOptions) GetWildcardOption() WildcardOption {
	return opts.wildcardOption

}

// GetZoneSeparator returns the delimiter that separates the address from the zone, the default being '%'.
func (opts *ipStringOptions) GetZoneSeparator() string {
	return opts.zoneSeparator
}

// IPStringOptionsBuilder is used to create an immutable IPStringOptions instance for IP address strings.
type IPStringOptionsBuilder struct {
	StringOptionsBuilder
	ipStringOptions ipStringOptions
}

// SetAddressSuffix dictates a suffix to be appended to the string.
// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings.
func (builder *IPStringOptionsBuilder) SetAddressSuffix(suffix string) *IPStringOptionsBuilder {
	builder.ipStringOptions.addrSuffix = suffix
	return builder
}

// SetWildcardOptions is a convenient method for simultaneously setting both WildcardOption and Wildcards.
// It overrides previous calls to SetWildcardOption and SetWildcards,
// and is overridden by subsequent calls to these methods.
func (builder *IPStringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPStringOptionsBuilder {
	builder.SetWildcards(wildcardOptions.GetWildcards())
	return builder.SetWildcardOption(wildcardOptions.GetWildcardOption())
}

// SetWildcardOption sets the WildcardOption parameter for use in the string.
func (builder *IPStringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPStringOptionsBuilder {
	builder.ipStringOptions.wildcardOption = wildcardOption
	return builder
}

// SetWildcards defines wildcards to be used in the string.
func (builder *IPStringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

// SetZoneSeparator determines the separator to separate the zone from the address, the default is '%'.
// Zones only apply to IPv6 addresses, not IPv4 addresses.
func (builder *IPStringOptionsBuilder) SetZoneSeparator(separator string) *IPStringOptionsBuilder {
	builder.ipStringOptions.zoneSeparator = separator
	return builder
}

// SetExpandedSegments dictates whether segments should be expanded to maximal width, typically by using leading zeros.
func (builder *IPStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

// SetReverse determines whether to print the line segments in reverse order from the normal order,
// with the normal order being the order from largest to smallest value.
func (builder *IPStringOptionsBuilder) SetReverse(reverse bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetReverse(reverse)
	return builder
}

// SetUppercase determines whether to use uppercase for hexadecimal or other alphabetic radians.
func (builder *IPStringOptionsBuilder) SetUppercase(uppercase bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

// SetRadix sets the radix to be used.
func (builder *IPStringOptionsBuilder) SetRadix(base int) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetRadix(base)
	return builder
}

// SetHasSeparator determines whether there is a separator.
// By default the IPStringOptionsBuilder is set to false.
func (builder *IPStringOptionsBuilder) SetHasSeparator(has bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// SetSeparator specifies the separator to separate address partitions.
// HasSeparator specifies whether this separator should be used or not.
func (builder *IPStringOptionsBuilder) SetSeparator(separator byte) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSeparator(separator)
	return builder
}

// SetAddressLabel dictates a string to add to the entire address string,
// such as an octal, hexadecimal or binary prefix.
func (builder *IPStringOptionsBuilder) SetAddressLabel(label string) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetAddressLabel(label)
	return builder
}

// ToOptions returns an immutable instance of IPStringOptions constructed by this constructor.
func (builder *IPStringOptionsBuilder) ToOptions() IPStringOptions {
	builder.ipStringOptions.zoneSeparator = getIPDefaults(builder.ipStringOptions.zoneSeparator)
	res := builder.ipStringOptions
	res.stringOptions = *builder.StringOptionsBuilder.ToOptions().(*stringOptions)
	return &res
}

// SetSegmentStrPrefix dictates a string prefix to add to each segment value,
// such as an octal, hexadecimal, or binary prefix.
func (builder *IPStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

// The IPv4StringOptionsBuilder is used to create an immutable IPStringOptions instance for IPv4 address strings.
type IPv4StringOptionsBuilder struct {
	IPStringOptionsBuilder
}

// SetAddressSuffix dictates a suffix to be appended to the string.
// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings.
func (builder *IPv4StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressSuffix(suffix)
	return builder
}

// SetWildcardOptions is a convenient method for simultaneously setting both WildcardOption and Wildcards.
// It overrides previous calls to SetWildcardOption and SetWildcards,
// and is overridden by subsequent calls to these methods.
func (builder *IPv4StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
	return builder.SetWildcardOption(wildcardOptions.GetWildcardOption())
}

// SetWildcardOption sets the WildcardOption parameter for use in the string.
func (builder *IPv4StringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOption(wildcardOption)
	return builder
}

// SetWildcards defines wildcards to be used in the string.
func (builder *IPv4StringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

// SetReverse determines whether to print the line segments in reverse order from the normal order,
// with the normal order being the order from largest to smallest value.
func (builder *IPv4StringOptionsBuilder) SetReverse(reverse bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetReverse(reverse)
	return builder
}

// SetUppercase determines whether to use uppercase for hexadecimal or other alphabetic radians.
func (builder *IPv4StringOptionsBuilder) SetUppercase(uppercase bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

// SetRadix sets the radix to be used.
func (builder *IPv4StringOptionsBuilder) SetRadix(base int) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetRadix(base)
	return builder
}

// SetExpandedSegments determines whether segments should be expanded to their maximum width,
// usually with leading zeros.
func (builder *IPv4StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

// SetHasSeparator dictates whether there is a separator.
// The default for IPv4 is true.
func (builder *IPv4StringOptionsBuilder) SetHasSeparator(has bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// SetSeparator defines a separator to separate parts of the address, for IPv4 the default is '.'.
// HasSeparator specifies whether to use this separator or not.
func (builder *IPv4StringOptionsBuilder) SetSeparator(separator byte) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSeparator(separator)
	return builder
}

// SetAddressLabel dictates a string to add to the entire address string,
// such as an octal, hexadecimal or binary prefix.
func (builder *IPv4StringOptionsBuilder) SetAddressLabel(label string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressLabel(label)
	return builder
}

// SetSegmentStrPrefix dictates a string prefix to add to each segment value,
// such as an octal, hexadecimal, or binary prefix.
func (builder *IPv4StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

// ToOptions returns an immutable IPStringOptions instance built by this builder.
func (builder *IPv4StringOptionsBuilder) ToOptions() IPStringOptions {
	b := &builder.StringOptionsBuilder
	b.hasSeparator, b.separator, b.base = getIPv4Defaults(b.hasSeparator, b.separator, b.base)
	return builder.IPStringOptionsBuilder.ToOptions()
}

// IPv6StringOptions provides a clear way to create a specific type of IPv6 address string.
type IPv6StringOptions interface {
	IPStringOptions
	// GetIPv4Opts returns the parameters used to create an embedded IPv4 address string in a mixed IPv6 address,
	// which is taken from the last 32 bits of the IPv6 address.
	// For example: "a:b:c:d:e:f:1.2.3.4".
	GetIPv4Opts() IPStringOptions
	// GetCompressOptions returns CompressOptions parameters that specify how to compress null segments in an IPv6 address string or subnet.
	GetCompressOptions() CompressOptions
	// IsSplitDigits specifies whether each digit is separated from each other by separators.
	// If separated, this parameter is ignored.
	// Can produce address_error.IncompatibleAddressError for ranged series.
	IsSplitDigits() bool
	// IsMixed specifies that the last two segments of the IPv6 address should be printed as IPv4 address, resulting in a mixed IPv6/v4 string.
	// Can produce address_error.IncompatibleAddressError for ranges in the IPv4 part of the series.
	IsMixed() bool
}

type ipv6StringOptions struct {
	ipStringOptions
	ipv4Opts        IPStringOptions
	compressOptions CompressOptions // can be nil, which means no compression
	splitDigits     bool
}

// IsSplitDigits indicates whether each digit is separated from each other by separators.
// If mixed, this option is ignored.
func (opts *ipv6StringOptions) IsSplitDigits() bool {
	return opts.splitDigits
}

// GetIPv4Opts returns the IPv4 string options to be used in the IPv4 address section of a mixed IPv6/v4 string.
func (opts *ipv6StringOptions) GetIPv4Opts() IPStringOptions {
	return opts.ipv4Opts
}

// GetCompressOptions returns CompressOptions parameters that specify how to compress null segments in an IPv6 address string or subnet.
func (opts *ipv6StringOptions) GetCompressOptions() CompressOptions {
	return opts.compressOptions
}

// IsMixed specifies that the last two segments of the IPv6 address should be printed as IPv4 address, resulting in a mixed IPv6/v4 string.
func (opts *ipv6StringOptions) IsMixed() bool {
	return opts.ipv4Opts != nil
}

// IPv6StringOptionsBuilder is used to create an immutable IPv6StringOptions instance for IPv6 address strings.
type IPv6StringOptionsBuilder struct {
	opts ipv6StringOptions
	IPStringOptionsBuilder
	makeMixed bool
}

// IsMixed specifies whether the last two segments of the IPv6 address should be printed as IPv4 address, resulting in a mixed IPv6/v4 string.
func (builder *IPv6StringOptionsBuilder) IsMixed() bool {
	return builder.makeMixed
}

// GetIPv4Opts returns the IPv4 string options to be used in the IPv4 address section of a mixed IPv6/v4 string.
func (builder *IPv6StringOptionsBuilder) GetIPv4Opts() IPStringOptions {
	return builder.opts.ipv4Opts
}

// GetCompressOptions returns CompressOptions parameters that specify how to compress null segments in an IPv6 address string or subnet.
func (builder *IPv6StringOptionsBuilder) GetCompressOptions() CompressOptions {
	return builder.opts.compressOptions
}

// SetCompressOptions sets the CompressOptions parameters, which determine how to compress null segments in the IPv6 address string or subnet.
func (builder *IPv6StringOptionsBuilder) SetCompressOptions(compressOptions CompressOptions) *IPv6StringOptionsBuilder {
	builder.opts.compressOptions = compressOptions
	return builder
}

// SetSplitDigits determines whether to separate each digit from each other with separators.
// When mixed, this parameter is ignored.
func (builder *IPv6StringOptionsBuilder) SetSplitDigits(splitDigits bool) *IPv6StringOptionsBuilder {
	builder.opts.splitDigits = splitDigits
	return builder
}

// SetMixed determines whether the string should be a mixed IPv6/v4 string in which the last two segments of the IPv6 address should be printed as an IPv4 address.
func (builder *IPv6StringOptionsBuilder) SetMixed(makeMixed bool) *IPv6StringOptionsBuilder {
	builder.makeMixed = makeMixed
	return builder
}

// SetMixedOptions provides the IPv4 options to be used in the IPv4 mixed string section.
// Calling this method sets the string as an IPv6/v4 mixed string.
func (builder *IPv6StringOptionsBuilder) SetMixedOptions(ipv4Options IPStringOptions) *IPv6StringOptionsBuilder {
	builder.makeMixed = true
	builder.opts.ipv4Opts = ipv4Options
	return builder
}

// SetWildcardOptions is a convenient method for simultaneously setting WildcardOption and Wildcards.
// It overrides previous calls to SetWildcardOption and SetWildcards and is overridden by subsequent calls to these methods.
func (builder *IPv6StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
	return builder
}

// SetWildcardOption sets the WildcardOption parameter for use in the string.
func (builder *IPv6StringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOption(wildcardOption)
	return builder
}

// SetWildcards defines wildcards to be used in the string.
func (builder *IPv6StringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

// SetExpandedSegments determines whether segments should be expanded to their maximum width, usually with leading zeros.
func (builder *IPv6StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

// SetRadix sets the radix to be used.
func (builder *IPv6StringOptionsBuilder) SetRadix(base int) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetRadix(base)
	return builder
}

// SetHasSeparator determines whether there is a separator.
// The default for IPv6 is true.
func (builder *IPv6StringOptionsBuilder) SetHasSeparator(has bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// SetSeparator defines a separator to separate parts of the address, for IPv6 the default is ':'.
// HasSeparator specifies whether to use this separator or not.
func (builder *IPv6StringOptionsBuilder) SetSeparator(separator byte) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSeparator(separator)
	return builder
}

// SetZoneSeparator determines the separator to separate the zone from the address, the default is '%'.
func (builder *IPv6StringOptionsBuilder) SetZoneSeparator(separator string) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetZoneSeparator(separator)
	return builder
}

// SetAddressSuffix determines the suffix to be added to the string.
// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of
// suffixes added to the end of address strings.
func (builder *IPv6StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressSuffix(suffix)
	return builder
}

// SetSegmentStrPrefix dictates a string prefix to add to each segment value, such as an octal, hexadecimal, or binary prefix.
func (builder *IPv6StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

// SetReverse determines whether to print the line segments in reverse order from the normal order,
// with the normal order being the order from largest to smallest value.
func (builder *IPv6StringOptionsBuilder) SetReverse(reverse bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetReverse(reverse)
	return builder
}

// SetUppercase determines whether to use uppercase for hexadecimal or other alphabetic radians.
func (builder *IPv6StringOptionsBuilder) SetUppercase(upper bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetUppercase(upper)
	return builder
}

// ToOptions returns an immutable instance of IPv6StringOptions constructed by this constructor.
func (builder *IPv6StringOptionsBuilder) ToOptions() IPv6StringOptions {
	if builder.makeMixed {
		if builder.opts.ipv4Opts == nil {
			builder.opts.ipv4Opts = new(IPv4StringOptionsBuilder).SetExpandedSegments(builder.expandSegments).
				SetWildcardOption(builder.ipStringOptions.wildcardOption).
				SetWildcards(builder.wildcards).ToOptions()
		}
	} else {
		builder.opts.ipv4Opts = nil
	}
	b := &builder.IPStringOptionsBuilder.StringOptionsBuilder
	b.hasSeparator, b.separator = getIPv6Defaults(b.hasSeparator, b.separator)
	res := builder.opts
	res.ipStringOptions = *builder.IPStringOptionsBuilder.ToOptions().(*ipStringOptions)
	return &res
}

// CompressionChoiceOptions specify which null segments are to be compressed.
type CompressionChoiceOptions string

// CompressHost specifies whether to compress the host with the prefix address.
func (choice CompressionChoiceOptions) CompressHost() bool {
	return choice != ZerosCompression
}

// MixedCompressionOptions specify which null segments should be compressed in mixed IPv6/v4 strings.
type MixedCompressionOptions string

// CompressOptions specifies how to compress zero-segments in the address or subnet string.
type CompressOptions interface {
	// GetCompressionChoiceOptions provides CompressionChoiceOptions that determine which null segments should be compressed.
	GetCompressionChoiceOptions() CompressionChoiceOptions
	// GetMixedCompressionOptions provides MixedCompressionOptions options that specify which null segments should be compressed in mixed IPv6/v4 strings.
	GetMixedCompressionOptions() MixedCompressionOptions
	// CompressSingle specifies whether one zero segment should compress itself if there are no other segments to compress.
	CompressSingle() bool
}

type compressOptions struct {
	compressSingle       bool
	rangeSelection       CompressionChoiceOptions
	compressMixedOptions MixedCompressionOptions // params for addresses with an ipv4 section
}

// GetCompressionChoiceOptions provides CompressionChoiceOptions that determine which null segments should be compressed.
func (opts *compressOptions) GetCompressionChoiceOptions() CompressionChoiceOptions {
	return opts.rangeSelection
}

// GetMixedCompressionOptions provides MixedCompressionOptions options that specify which null segments should be compressed in mixed IPv6/v4 strings.
func (opts *compressOptions) GetMixedCompressionOptions() MixedCompressionOptions {
	return opts.compressMixedOptions
}

// CompressSingle specifies whether one zero segment should compress itself if there are no other segments to compress.
func (opts *compressOptions) CompressSingle() bool {
	return opts.compressSingle
}

// The CompressOptionsBuilder is used to create an immutable CompressOptions instance for IPv6 address strings.
type CompressOptionsBuilder struct {
	compressOptions
}

// SetCompressSingle determines whether one zero segment should compress itself if there are no other segments to compress.
func (builder *CompressOptionsBuilder) SetCompressSingle(compressSingle bool) *CompressOptionsBuilder {
	builder.compressSingle = compressSingle
	return builder
}

// SetCompressionChoiceOptions sets the CompressionChoiceOptions that determine which null segments should be compressed.
func (builder *CompressOptionsBuilder) SetCompressionChoiceOptions(rangeSelection CompressionChoiceOptions) *CompressOptionsBuilder {
	builder.rangeSelection = rangeSelection
	return builder
}

// SetMixedCompressionOptions sets the MixedCompressionOptions parameters that determine
// which null segments should be compressed in mixed IPv6/v4 strings.
func (builder *CompressOptionsBuilder) SetMixedCompressionOptions(compressMixedOptions MixedCompressionOptions) *CompressOptionsBuilder {
	builder.compressMixedOptions = compressMixedOptions
	return builder
}

// ToOptions returns an immutable instance of CompressOptions.
func (builder *CompressOptionsBuilder) ToOptions() CompressOptions {
	res := builder.compressOptions
	return &res
}

func getDefaults(radix int, wildcards Wildcards, separator byte) (int, Wildcards, byte) {
	if radix == 0 {
		radix = 16
	}

	if wildcards == nil {
		wildcards = DefaultWildcards
	}

	if separator == 0 {
		separator = ' '
	}
	return radix, wildcards, separator
}

func getMACDefaults(hasSeparator *bool, separator byte) (*bool, byte) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}

	if separator == 0 {
		separator = macColonSegmentSeparator
	}
	return hasSeparator, separator
}

func getIPDefaults(zoneSeparator string) string {
	if len(zoneSeparator) == 0 {
		zoneSeparator = ipv6ZoneSeparatorStr
	}
	return zoneSeparator
}

func getIPv4Defaults(hasSeparator *bool, separator byte, radix int) (*bool, byte, int) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}

	if radix == 0 {
		radix = 10
	}

	if separator == 0 {
		separator = ipv4SegmentSeparator
	}
	return hasSeparator, separator, radix
}

func getIPv6Defaults(hasSeparator *bool, separator byte) (*bool, byte) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}

	if separator == 0 {
		separator = ipv6SegmentSeparator
	}
	return hasSeparator, separator
}
