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
	ipv4Network = &ipv4AddressNetwork{
		ipAddressNetwork: ipAddressNetwork{
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
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

type ipv4AddressNetwork struct {
	ipAddressNetwork
	creator ipv4AddressCreator
}
