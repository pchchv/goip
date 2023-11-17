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

// IPAddressConverter converts IP addresses to either IPv4 or IPv6.
type IPAddressConverter interface {
	IPv4AddressConverter
	IPv6AddressConverter
	// IsIPv4Convertible returns whether the address is IPv4 or can be converted to IPv4.
	// If true, ToIPv4 returns non-nil.
	IsIPv4Convertible(address *IPAddress) bool
	// IsIPv6Convertible returns whether the address is IPv6 or can be converted to IPv6.
	// If true, ToIPv6 returns non-nil.
	IsIPv6Convertible(address *IPAddress) bool
}
