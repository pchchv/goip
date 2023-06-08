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

// IPAddress represents an IP address or subnet, either IPv4 or IPv6 (except zero IPAddress, which is neither).
// An IP address consists of segments that have a range of values and may additionally have an associated prefix length.
// An IPAddress with a null value has no segments, neither IPv4 nor IPv6,
// which is not compatible with a null value for IPv4 or IPv6, which are 0.0.0.0 and :: respectively.
// The null value is also known as adaptive zero.
// To create it from a string, use NewIPAddressString and then use the ToAddress or GetAddress method from [IPAddressString].
type IPAddress struct {
	ipAddressInternal
}

// IsIPv4 returns true if this represents version 4.
func (version IPVersion) IsIPv4() bool {
	return len(version) == 4 && strings.EqualFold(string(version), string(IPv4))
}

// IsIPv6 returns true if this represents version 6.
func (version IPVersion) IsIPv6() bool {
	return len(version) == 4 && strings.EqualFold(string(version), string(IPv6))
}

// IsIndeterminate returns true if this represents an unspecified IP address version.
func (version IPVersion) IsIndeterminate() bool {
	if len(version) == 4 {
		// allow mixed case when converting string event code to IPVersion
		dig := version[3]
		if dig != '4' && dig != '6' {
			return true
		}

		dig = version[0]
		if dig != 'I' && dig != 'i' {
			return true
		}

		dig = version[1]
		if dig != 'P' && dig != 'p' {
			return true
		}

		dig = version[2]
		if dig != 'v' && dig != 'V' {
			return true
		}
		return false
	}
	return true
}

// Equal returns true if the given version matches this version.
// Two indeterminate versions always match, even if their associated strings do not.
func (version IPVersion) Equal(other IPVersion) bool {
	return strings.EqualFold(string(version), string(other)) || (version.IsIndeterminate() && other.IsIndeterminate())
}

// String returns "IPv4", "IPv6" or the nil-value ("") representing an indeterminate version.
func (version IPVersion) String() string {
	return string(version)
}
