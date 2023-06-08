package goip

// IPAddress represents an IP address or subnet, either IPv4 or IPv6 (except zero IPAddress, which is neither).
// An IP address consists of segments that have a range of values and may additionally have an associated prefix length.
// An IPAddress with a null value has no segments, neither IPv4 nor IPv6,
// which is not compatible with a null value for IPv4 or IPv6, which are 0.0.0.0 and :: respectively.
// The null value is also known as adaptive zero.
// To create it from a string, use NewIPAddressString and then use the ToAddress or GetAddress method from [IPAddressString].
type IPAddress struct {
	ipAddressInternal
}
