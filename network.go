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
