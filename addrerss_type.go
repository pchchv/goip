package goip

// addressType keeps track of which address divisions and groups
// of address divisions can be converted to higher-level types.
type addressType byte

const (
	zeroType        addressType = 0 // no segments
	ipv4Type        addressType = 1 // ipv4 segments
	ipv6Type        addressType = 2 // ipv6 segments
	ipv6v4MixedType addressType = 3 // ipv6-v4 mixed segments
	macType         addressType = 4 // mac segments
)

func (a addressType) isIPv4() bool {
	return a == ipv4Type
}

func (a addressType) isIPv6() bool {
	return a == ipv6Type
}

func (a addressType) isIPv6v4Mixed() bool {
	return a == ipv6v4MixedType
}

func (a addressType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addressType) isMAC() bool {
	return a == macType
}

func (a addressType) isZeroSegments() bool {
	return a == zeroType
}
