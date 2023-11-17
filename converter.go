package goip

// IPv6AddressConverter converts IP addresses to IPv6.
type IPv6AddressConverter interface {
	// ToIPv6 converts to IPv6.
	// If the given address is IPv6, or can be converted to IPv6,
	// returns that IPv6Address.
	// Otherwise, returns nil.
	ToIPv6(address *IPAddress) *IPv6Address
}

// IPv4AddressConverter converts IP addresses to IPv4.
type IPv4AddressConverter interface {
	// ToIPv4 converts to IPv4.
	// If the given address is IPv4,
	// or can be converted to IPv4,
	// returns that IPv4Address.
	// Otherwise, returns nil.
	ToIPv4(address *IPAddress) *IPv4Address
}
