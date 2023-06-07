package goip

import "strings"

const (
	// IPv4 represents Internet Protocol version 4
	IPv4 IPVersion = "IPv4"
	// IPv6 represents Internet Protocol version 6
	IPv6 IPVersion = "IPv6"
)

// IPVersion is the version type used by IP address types.
type IPVersion string

// IsIPv4 returns true if this represents version 4
func (version IPVersion) IsIPv4() bool {
	return len(version) == 4 && strings.EqualFold(string(version), string(IPv4))
}

// IsIPv6 returns true if this represents version 6
func (version IPVersion) IsIPv6() bool {
	return len(version) == 4 && strings.EqualFold(string(version), string(IPv6))
}
