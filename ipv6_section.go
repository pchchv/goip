package goip

// IPv6v4MixedAddressGrouping has divisions that are a mix of IPv6 and IPv4 sections.
// It has an initial IPv6 section followed by an IPv4 section.
type IPv6v4MixedAddressGrouping struct {
	addressDivisionGroupingInternal
}

// IsMultiple returns  whether this grouping represents multiple values.
func (grouping *IPv6v4MixedAddressGrouping) IsMultiple() bool {
	return grouping != nil && grouping.isMultiple()
}

// IsPrefixed returns whether this grouping has an associated prefix length.
func (grouping *IPv6v4MixedAddressGrouping) IsPrefixed() bool {
	return grouping != nil && grouping.isPrefixed()
}

// ToDivGrouping converts to AddressDivisionGrouping, a polymorphic type used with all address sections and divisional groupings.
// The reverse conversion can then be performed using ToMixedIPv6v4.
//
// ToDivGrouping can be called with a nil receiver, allowing this method to be used in a chain with methods that can return a nil pointer.
func (grouping *IPv6v4MixedAddressGrouping) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(grouping)
}
