package goip

var (
	ipv6Network = &ipv6AddressNetwork{
		ipAddressNetwork: ipAddressNetwork{
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
		},
	}
	IPv6Network = &IPv6AddressNetwork{ipv6Network}
)

type addressNetwork interface {
	getAddressCreator() parsedAddressCreator
}

// IPAddressNetwork represents a network of addresses of a single IP version providing a
// collection of standard address components for that version,
// such as masks and loopbacks.
type IPAddressNetwork interface {
	GetLoopback() *IPAddress
	GetNetworkMask(prefixLength BitCount) *IPAddress
	GetPrefixedNetworkMask(prefixLength BitCount) *IPAddress
	GetHostMask(prefixLength BitCount) *IPAddress
	GetPrefixedHostMask(prefixLength BitCount) *IPAddress
	getIPAddressCreator() ipAddressCreator
	addressNetwork
}

type ipAddressNetwork struct {
	subnetsMasksWithPrefix []*IPAddress
	subnetMasks            []*IPAddress
	hostMasksWithPrefix    []*IPAddress
	hostMasks              []*IPAddress
}

type ipv6AddressNetwork struct {
	ipAddressNetwork
	creator ipv6AddressCreator
}

// IPv6AddressNetwork is the implementation of IPAddressNetwork for IPv6
type IPv6AddressNetwork struct {
	*ipv6AddressNetwork
}

type ipv4AddressCreator struct{}

func (creator *ipv4AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv4MaxValuePerSegment
}

func (creator *ipv4AddressCreator) createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4RangePrefixedSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToDiv()
}

func (creator *ipv4AddressCreator) createRangeSegment(lower, upper SegInt) *AddressDivision {
	return NewIPv4RangeSegment(IPv4SegInt(lower), IPv4SegInt(upper)).ToDiv()
}

func (creator *ipv4AddressCreator) createSegmentInternal(value SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalVal SegInt, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int) *AddressDivision {
	seg := NewIPv4PrefixedSegment(IPv4SegInt(value), segmentPrefixLength)
	seg.setStandardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	seg.setWildcardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal)
	return seg.toAddressDivision()
}

func (creator *ipv4AddressCreator) createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
	originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
	lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision {
	seg := NewIPv4RangePrefixedSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength)
	seg.setRangeStandardString(addressStr, isStandardString, isStandardRangeString, lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex, originalLower, originalUpper)
	seg.setRangeWildcardString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper)
	return seg.ToDiv()
}

func (creator *ipv4AddressCreator) createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision {
	return NewIPv4PrefixedSegment(IPv4SegInt(value), segmentPrefixLength).ToDiv()
}

func (creator *ipv4AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection {
	return newPrefixedIPv4SectionParsed(segments, isMultiple, prefixLength, false).ToIP()
}

func (creator *ipv4AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection {
	return newPrefixedIPv4SectionParsed(segments, isMultiple, prefixLength, true).ToIP()
}
