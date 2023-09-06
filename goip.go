package goip

import (
	"math/big"
	"strings"
	"unsafe"
)

const (
	// IndeterminateIPVersion represents an unspecified IP address version
	IndeterminateIPVersion IPVersion = ""
	// IPv4 represents Internet Protocol version 4
	IPv4 IPVersion = "IPv4"
	// IPv6 represents Internet Protocol version 6
	IPv6 IPVersion = "IPv6"
)

var zeroIPAddr = createIPAddress(zeroSection, NoZone)

// IPAddress represents an IP address or subnet, either IPv4 or IPv6 (except zero IPAddress, which is neither).
// An IP address consists of segments that have a range of values and may additionally have an associated prefix length.
// An IPAddress with a null value has no segments, neither IPv4 nor IPv6,
// which is not compatible with a null value for IPv4 or IPv6, which are 0.0.0.0 and :: respectively.
// The null value is also known as adaptive zero.
// To create it from a string, use NewIPAddressString and then use the ToAddress or GetAddress method from [IPAddressString].
type IPAddress struct {
	ipAddressInternal
}

func (addr *IPAddress) init() *IPAddress {
	if addr.section == nil {
		return zeroIPAddr // this has a zero section
	}
	return addr
}

// ToIP is an identity method.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPAddress) ToIP() *IPAddress {
	return addr
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToIP.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPAddress) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

// IPVersion is the version type used by IP address types.
type IPVersion string

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

// GetByteCount returns the number of bytes comprising an address of this IP Version.
func (version IPVersion) GetByteCount() int {
	if version.IsIPv4() {
		return IPv4ByteCount
	} else if version.IsIPv6() {
		return IPv6ByteCount
	}
	return 0
}

// GetBitCount returns the number of bits comprising an address of this IP Version.
func (version IPVersion) GetBitCount() BitCount {
	if version.IsIPv4() {
		return IPv4BitCount
	} else if version.IsIPv6() {
		return IPv6BitCount
	}
	return 0
}

// necessary to avoid direct access to IPAddress
type ipAddressInternal struct {
	addressInternal
}

func (addr *ipAddressInternal) toIPAddress() *IPAddress {
	return (*IPAddress)(unsafe.Pointer(addr))
}

// GetPrefixCount returns the count of prefixes in this address or subnet.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the count of the range of values in the prefix.
//
// If this has a nil prefix length, returns the same value as GetCount.
func (addr *ipAddressInternal) GetPrefixCount() *big.Int {
	return addr.addressInternal.GetPrefixCount()
}

// GetPrefixCountLen returns the count of prefixes in this address or subnet for the given prefix length.
//
// If not a subnet of multiple addresses, or a subnet with just single prefix of the given length, returns 1.
func (addr *ipAddressInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	return addr.addressInternal.GetPrefixCountLen(prefixLen)
}

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
func (addr *ipAddressInternal) GetBlockCount(segments int) *big.Int {
	return addr.addressInternal.GetBlockCount(segments)
}

// GetPrefixLen returns the prefix length, or nil if there is no prefix length.
//
// A prefix length indicates the number of bits in the initial part of the address that comprise the prefix.
//
// A prefix is a part of the address that is not specific to that address but common amongst a group of addresses,
// such as a CIDR prefix block subnet.
//
// For IP addresses, the prefix is explicitly defined when the address is created.
// For example, "1.2.0.0/16" has a prefix length of 16, while "1.2.*.*" has no prefix length,
// even though they both represent the same set of addresses and are considered equal.
// Prefixes can be considered variable for a given IP address and can depend on routing.
//
// The methods GetMinPrefixLenForBlock and GetPrefixLenForSingleBlock can help you
// to obtain or define a prefix length if one does not exist already.
// The method ToPrefixBlockLen allows you to create the subnet consisting of
// the block of addresses for any given prefix length.
func (addr *ipAddressInternal) GetPrefixLen() PrefixLen {
	return addr.addressInternal.GetPrefixLen()
}

// isIP returns whether this matches an IP address.
// It must be IPv4, IPv6, or the zero IPAddress which has no segments
// we allow nil receivers to allow this to be called following a failed conversion like ToIP()
func (addr *addressInternal) isIP() bool {
	return addr.section == nil || addr.section.matchesIPAddressType()
}

// GetBlockMaskPrefixLen returns the prefix length if this address is equivalent to the mask for a CIDR prefix block.
// Otherwise, it returns nil.
// A CIDR network mask is an address with all ones in the network section and then all zeros in the host section.
// A CIDR host mask is an address with all zeros in the network section and then all ones in the host section.
// The prefix length is the bit-length of the network section.
//
// Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length of this instance,
// indicating the network and host section of this address.
// The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
// section of any other address.  Therefore, the two values can be different values, or one can be nil while the other is not.
//
// This method applies only to the lower value of the range if this address represents multiple values.
func (addr *ipAddressInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	section := addr.section
	if section == nil {
		return nil
	}
	return section.ToIP().GetBlockMaskPrefixLen(network)
}

func createIPAddress(section *AddressSection, zone Zone) *IPAddress {
	return &IPAddress{
		ipAddressInternal{
			addressInternal{
				section: section,
				zone:    zone,
				cache:   &addressCache{},
			},
		},
	}
}
