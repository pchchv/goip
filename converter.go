package goip

// IPv6AddressConverter converts IP addresses to IPv6.
type IPv6AddressConverter interface {
	// ToIPv6 converts to IPv6.
	// If the given address is IPv6, or can be converted to IPv6,
	// returns that IPv6Address.
	// Otherwise, returns nil.
	ToIPv6(address *IPAddress) *IPv6Address
}
