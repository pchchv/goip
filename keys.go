package goip

import "fmt"

const (
	adaptiveZeroScheme addressScheme = 0 // adaptiveZeroScheme needs to be zero, to coincide with the zero value for Address and IPAddress, which is a zero-length address
	ipv4Scheme         addressScheme = 1
	ipv6Scheme         addressScheme = 2
	mac48Scheme        addressScheme = 3
	eui64Scheme        addressScheme = 4
)

var (
	_ IPv4AddressKey
	_ IPv6AddressKey
	_ MACAddressKey

	_ Key[*IPv4Address]
	_ Key[*IPv6Address]
	_ Key[*MACAddress]

	// ensure our 5 key types are indeed comparable
	_ testComparableConstraint[IPv4AddressKey]
	_ testComparableConstraint[IPv6AddressKey]
	_ testComparableConstraint[MACAddressKey]
	_ testComparableConstraint[Key[*IPAddress]]
	_ testComparableConstraint[Key[*Address]]
)

// SequentialRangeKey is a representation of SequentialRange that is comparable as defined by the language specification.
//
// It can be used as a map key.
// The zero value is a range from a zero-length address to itself.
type SequentialRangeKey[T SequentialRangeConstraint[T]] struct {
	vals [2]struct {
		lower,
		upper uint64
	}
	addrType addrType // only used when T is *IPAddress to indicate version for non-zero valued address
}

// ToSeqRange converts back to a sequential range instance.
func (key SequentialRangeKey[T]) ToSeqRange() *SequentialRange[T] {
	var isMult bool
	var lower, upper T
	anyt := any(lower)
	isIP, isIPv4, isIPv6 := false, false, false
	if _, isIPv4 = anyt.(*IPv4Address); !isIPv4 {
		if _, isIPv6 = anyt.(*IPv6Address); !isIPv6 {
			if _, isIP = anyt.(*IPAddress); isIP {
				addressType := key.addrType
				if isIPv4 = addressType.isIPv4(); !isIPv4 {
					if isIPv6 = addressType.isIPv6(); !isIPv6 {
						if isNeither := addressType.isZeroSegments(); isNeither {
							lower = any(zeroIPAddr).(T)
							upper = lower
						} else {
							panic("supports only IP addresses")
						}
					}
				}
			} else {
				panic("supports only IP addresses")
			}
		}
	}

	if isIPv6 {
		lower6 := NewIPv6AddressFromVals(
			func(segmentIndex int) IPv6SegInt {
				valsIndex := segmentIndex >> 2
				segIndex := ((IPv6SegmentCount - 1) - segmentIndex) & 0x3
				return IPv6SegInt(key.vals[valsIndex].lower >> (segIndex << ipv6BitsToSegmentBitshift))
			})
		upper6 := NewIPv6AddressFromVals(
			func(segmentIndex int) IPv6SegInt {
				valsIndex := segmentIndex >> 2
				segIndex := ((IPv6SegmentCount - 1) - segmentIndex) & 0x3
				return IPv6SegInt(key.vals[valsIndex].upper >> (segIndex << ipv6BitsToSegmentBitshift))
			})
		isMult = key.vals[1].lower != key.vals[1].upper || key.vals[0].lower != key.vals[0].upper
		if isIP {
			lower = any(lower6.ToIP()).(T)
			upper = any(upper6.ToIP()).(T)
		} else {
			lower = any(lower6).(T)
			upper = any(upper6).(T)
		}
	} else if isIPv4 {
		l := uint32(key.vals[0].lower)
		u := uint32(key.vals[0].upper)
		lower4 := NewIPv4AddressFromUint32(l)
		upper4 := NewIPv4AddressFromUint32(u)
		isMult = l != u
		if isIP {
			lower = any(lower4.ToIP()).(T)
			upper = any(upper4.ToIP()).(T)
		} else {
			lower = any(lower4).(T)
			upper = any(upper4).(T)
		}
	}

	return newSequRangeUnchecked(lower, upper, isMult)
}

// String calls the String method in the corresponding sequential range.
func (key SequentialRangeKey[T]) String() string {
	return key.ToSeqRange().String()
}

// IPv4AddressKey is a representation of an IPv4 address that is comparable as defined by the language specification.
//
// It can be used as a map key.
// It can be obtained from its originating address instances.
// The zero value corresponds to the zero-value for IPv4Address.
// Keys do not incorporate prefix length to ensure that all equal addresses have equal keys.
// To create a key that has prefix length, combine into a struct with
// the PrefixKey obtained by passing the address into PrefixKeyFrom.
// IPv4Address can be compared using the Compare or Equal methods, or using an AddressComparator.
type IPv4AddressKey struct {
	vals uint64 // upper and lower combined into one uint64
}

type testComparableConstraint[T comparable] struct{}

type keyContents struct {
	vals [2]struct {
		lower,
		upper uint64
	}
	zone Zone
}

// IPv6AddressKey is a representation of an IPv6 address that is comparable as defined by the language specification.
//
// It can be used as a map key.  It can be obtained from its originating address instances.
// The zero value corresponds to the zero-value for IPv6Address.
// Keys do not incorporate prefix length to ensure that all equal addresses have equal keys.
// To create a key that has prefix length,
// combine into a struct with the PrefixKey obtained by passing the address into PrefixKeyFrom.
// IPv6Address can be compared using the Compare or Equal methods, or using an AddressComparator.
type IPv6AddressKey struct {
	keyContents
}

// MACAddressKey is a representation of a MAC address that is comparable as defined by the language specification.
//
// It can be used as a map key.  It can be obtained from its originating address instances.
// The zero value corresponds to the zero-value for MACAddress.
// Keys do not incorporate prefix length to ensure that all equal addresses have equal keys.
// To create a key that has prefix length,
// combine into a struct with the PrefixKey obtained by passing the address into PrefixKeyFrom.
// MACAddress can be compared using the Compare or Equal methods, or using an AddressComparator.
type MACAddressKey struct {
	vals struct {
		lower,
		upper uint64
	}
	additionalByteCount uint8 // 0 for MediaAccessControlSegmentCount or 2 for ExtendedUniqueIdentifier64SegmentCount
}

type addressScheme byte

// KeyConstraint is the generic type constraint for
// an address type that can be generated from a generic address key.
type KeyConstraint[T any] interface {
	fmt.Stringer
	fromKey(addressScheme, *keyContents) T // implemented by IPAddress and Address
}

// KeyGeneratorConstraint is the generic type constraint for
// an address type that can generate a generic address key.
type KeyGeneratorConstraint[T KeyConstraint[T]] interface {
	ToGenericKey() Key[T]
}

// GenericKeyConstraint is the generic type constraint for
// an address type that can generate and
// be generated from a generic address key.
type GenericKeyConstraint[T KeyConstraint[T]] interface {
	KeyGeneratorConstraint[T]
	KeyConstraint[T]
}

// Key is a representation of an address that is comparable as defined by the language specification.
//
// It can be used as a map key.  It can be obtained from its originating address instances.
// The zero value corresponds to the zero-value for its generic address type.
// Keys do not incorporate prefix length to ensure that all equal addresses have equal keys.
// To create a key that has prefix length,
// combine into a struct with the PrefixKey obtained by passing the address into PrefixKeyFrom.
type Key[T KeyConstraint[T]] struct {
	scheme addressScheme
	keyContents
}

// ToAddress converts back to an address instance.
func (key Key[T]) ToAddress() T {
	var t T
	return t.fromKey(key.scheme, &key.keyContents)
}

// String calls the String method in the corresponding address.
func (key Key[T]) String() string {
	return key.ToAddress().String()
}

type (
	AddressKey             = Key[*Address]
	IPAddressKey           = Key[*IPAddress]
	IPAddressSeqRangeKey   = SequentialRangeKey[*IPAddress]
	IPv4AddressSeqRangeKey = SequentialRangeKey[*IPv4Address]
	IPv6AddressSeqRangeKey = SequentialRangeKey[*IPv6Address]
)
