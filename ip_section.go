package goip

import "github.com/pchchv/goip/address_string"

var (
	rangeWildcard                 = new(address_string.WildcardsBuilder).ToWildcards()
	allWildcards                  = new(address_string.WildcardOptionsBuilder).SetWildcardOptions(address_string.WildcardsAll).ToOptions()
	wildcardsRangeOnlyNetworkOnly = new(address_string.WildcardOptionsBuilder).SetWildcards(rangeWildcard).ToOptions()
	allSQLWildcards               = new(address_string.WildcardOptionsBuilder).SetWildcardOptions(address_string.WildcardsAll).SetWildcards(
		new(address_string.WildcardsBuilder).SetWildcard(SegmentSqlWildcardStr).SetSingleWildcard(SegmentSqlSingleWildcardStr).ToWildcards()).ToOptions()
)

type ipAddressSectionInternal struct {
	addressSectionInternal
}

func (section *ipAddressSectionInternal) getNetworkPrefixLen() PrefixLen {
	return section.prefixLength
}

// GetNetworkPrefixLen returns the prefix length or nil if there is no prefix length.
// This is equivalent to GetPrefixLen.
//
// A prefix length indicates the number of bits in the initial part of the address item that make up the prefix.
//
// A prefix is a part of an address item that is not specific to a given address,
// but is common to a group of such items, such as the subnet of a CIDR prefix block.
func (section *ipAddressSectionInternal) GetNetworkPrefixLen() PrefixLen {
	return section.getNetworkPrefixLen().copy()
}

// IPAddressSection is the address section of an IP address containing a certain number of consecutive IP address segments.
// It represents a sequence of individual address segments.
// Each segment has the same bit length.
// Behind each address is an address section containing all address segments.
// IPAddressSection objects are immutable.
// This also makes them concurrency-safe.
// Most operations that can be performed on IPAddress instances can also be performed on IPAddressSection instances, and vice versa.
type IPAddressSection struct {
	ipAddressSectionInternal
}
