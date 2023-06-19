package goip

// addrType keeps track of which address divisions and groups
// of address divisions can be converted to higher-level types.
type addrType byte

const (
	zeroType        addrType = 0 // no segments
	ipv4Type        addrType = 1 // ipv4 segments
	ipv6Type        addrType = 2 // ipv6 segments
	ipv6v4MixedType addrType = 3 // ipv6-v4 mixed segments
	macType         addrType = 4 // mac segments
)

func (a addrType) isIPv4() bool {
	return a == ipv4Type
}

func (a addrType) isIPv6() bool {
	return a == ipv6Type
}

func (a addrType) isIPv6v4Mixed() bool {
	return a == ipv6v4MixedType
}

func (a addrType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addrType) isMAC() bool {
	return a == macType
}

func (a addrType) isZeroSegments() bool {
	return a == zeroType
}
