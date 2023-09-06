package goip

var (
	ipv4Network = &ipv4AddressNetwork{
		ipAddressNetwork: ipAddressNetwork{
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
			make([]*IPAddress, IPv4BitCount+1),
		},
	}
	ipv6Network = &ipv6AddressNetwork{
		ipAddressNetwork: ipAddressNetwork{
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
			make([]*IPAddress, IPv6BitCount+1),
		},
	}
	IPv4Network  = &IPv4AddressNetwork{ipv4Network}
	IPv6Network  = &IPv6AddressNetwork{ipv6Network}
	ipv4loopback = createIPv4Loopback()
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

func (network *ipv4AddressNetwork) getIPAddressCreator() ipAddressCreator {
	return &network.creator
}

func (network *ipv4AddressNetwork) getAddressCreator() parsedAddressCreator {
	return &network.creator
}

// IPv4AddressNetwork is the implementation of IPAddressNetwork for IPv4
type IPv4AddressNetwork struct {
	*ipv4AddressNetwork
}

func createIPv4Loopback() *IPv4Address {
	ipv4loopback, _ := NewIPv4AddressFromBytes([]byte{127, 0, 0, 1})
	return ipv4loopback
}
