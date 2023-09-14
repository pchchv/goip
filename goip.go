package goip

import (
	"math/big"
	"net"
	"strings"
	"unsafe"

	"github.com/pchchv/goip/address_error"
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

// IsIPv4 returns true if this address or subnet originated as an IPv4 address or subnet.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (addr *IPAddress) IsIPv4() bool {
	return addr != nil && addr.isIPv4()
}

// IsIPv6 returns true if this address or subnet originated as an IPv6 address or subnet.
// If so, use ToIPv6 to convert back to the IPv6-specific type.
func (addr *IPAddress) IsIPv6() bool {
	return addr != nil && addr.isIPv6()
}

// ToIPv4 converts to an IPv4Address if this address or subnet originated as an IPv4 address or subnet.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPAddress) ToIPv4() *IPv4Address {
	if addr.IsIPv4() {
		return (*IPv4Address)(addr)
	}
	return nil
}

// ToIPv6 converts to an IPv6Address if this address or subnet originated as an IPv6 address or subnet.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPAddress) ToIPv6() *IPv6Address {
	if addr.IsIPv6() {
		return (*IPv6Address)(addr)
	}
	return nil
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (addr *IPAddress) GetSegment(index int) *IPAddressSegment {
	return addr.getSegment(index).ToIP()
}

// GetSegmentCount returns the segment count, the number of segments in this address.
func (addr *IPAddress) GetSegmentCount() int {
	return addr.getDivisionCount()
}

// GetLower returns the lowest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for the subnet "1.2-3.4.5-6", the address "1.2.4.5" is returned.
func (addr *IPAddress) GetLower() *IPAddress {
	return addr.init().getLower().ToIP()
}

// GetUpper returns the highest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the series "1.3.4.6" is returned.
func (addr *IPAddress) GetUpper() *IPAddress {
	return addr.init().getUpper().ToIP()
}

// ToPrefixBlock returns the subnet associated with the prefix length of this address.
// If this address has no prefix length, this address is returned.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block".
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1.2.3.4/16" it returns the subnet "1.2.0.0/16", which can also be written as "1.2.*.*/16".
func (addr *IPAddress) ToPrefixBlock() *IPAddress {
	return addr.init().toPrefixBlock().ToIP()
}

// ToPrefixBlockLen returns the subnet associated with the given prefix length.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block" for that prefix length.
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1.2.3.4" and the prefix length provided is 16, it returns the subnet "1.2.0.0/16", which can also be written as "1.2.*.*/16".
func (addr *IPAddress) ToPrefixBlockLen(prefLen BitCount) *IPAddress {
	return addr.init().toPrefixBlockLen(prefLen).ToIP()
}

// GetCount returns the count of addresses that this address or subnet represents.
//
// If just a single address, not a subnet of multiple addresses, returns 1.
//
// For instance, the IP address subnet "2001:db8::/64" has the count of 2 to the power of 64.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *IPAddress) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address,
// whether it is a subnet of multiple addresses.
func (addr *IPAddress) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// GetSection returns the backing section for this address or subnet, comprising all segments.
func (addr *IPAddress) GetSection() *IPAddressSection {
	return addr.init().section.ToIP()
}

// GetDivisionCount returns the segment count.
func (addr *IPAddress) GetDivisionCount() int {
	return addr.getDivisionCount()
}

// GetBitCount returns the number of bits comprising this address,
// or each address in the range if a subnet, which is 32 for IPv4 and 128 for IPv6.
func (addr *IPAddress) GetBitCount() BitCount {
	if address := addr.ToIPv4(); address != nil {
		return address.GetBitCount()
	} else if address := addr.ToIPv6(); address != nil {
		return address.GetBitCount()
	}
	return addr.addressInternal.GetBitCount()
}

// GetByteCount returns the number of bytes required for this address,
// or each address in the range if a subnet, which is 4 for IPv4 and 16 for IPv6.
func (addr *IPAddress) GetByteCount() int {
	if address := addr.ToIPv4(); address != nil {
		return address.GetByteCount()
	} else if address := addr.ToIPv6(); address != nil {
		return address.GetByteCount()
	}
	return addr.addressInternal.GetByteCount()
}

// GetLowerIPAddress returns the address in the subnet or address collection with the lowest numeric value,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
// GetLowerIPAddress implements the IPAddressRange interface, and is equivalent to GetLower.
func (addr *IPAddress) GetLowerIPAddress() *IPAddress {
	return addr.GetLower()
}

// GetUpperIPAddress returns the address in the subnet or address collection with the highest numeric value,
// which will be the receiver if it represents a single address.
// For example, for the subnet "1.2-3.4.5-6", the address "1.3.4.6" is returned.
// GetUpperIPAddress implements the IPAddressRange interface, and is equivalent to GetUpper.
func (addr *IPAddress) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper()
}

// ToBlock creates a new block of addresses by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr *IPAddress) ToBlock(segmentIndex int, lower, upper SegInt) *IPAddress {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIP()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *IPAddress) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr *IPAddress) AdjustPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.init().adjustPrefixLen(prefixLen).ToIP()
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by
// the given increment while zeroing out the bits that have moved into or outside the prefix.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
//
// When prefix length is increased, the bits moved within the prefix become zero.
// When a prefix length is decreased, the bits moved outside the prefix become zero.
//
// For example, "1.2.0.0/16" adjusted by -8 becomes "1.0.0.0/8".
// "1.2.0.0/16" adjusted by 8 becomes "1.2.0.0/24".
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr *IPAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIP(), err
}

// Bytes returns the lowest address in this subnet or address as a byte slice.
func (addr *IPAddress) Bytes() []byte {
	return addr.init().section.Bytes()
}

// UpperBytes returns the highest address in this subnet or address as a byte slice.
func (addr *IPAddress) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

// GetNetIP returns the lowest address in this subnet or address as a net.IP.
func (addr *IPAddress) GetNetIP() net.IP {
	return addr.Bytes()
}

// GetUpperNetIP returns the highest address in this subnet or address as a net.IP.
func (addr *IPAddress) GetUpperNetIP() net.IP {
	return addr.UpperBytes()
}

// GetUpperNetIPAddr returns the highest address in this subnet or address as a net.IPAddr.
func (addr *IPAddress) GetUpperNetIPAddr() *net.IPAddr {
	return &net.IPAddr{
		IP:   addr.GetUpperNetIP(),
		Zone: string(addr.zone),
	}
}

// toAddressBase is needed for tries, it skips the init() call
func (addr *IPAddress) toAddressBase() *Address {
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

// GetSegmentCount returns the number of segments comprising an address of this IP Version: 4 for IPv4 and 8 for IPv6.
func (version IPVersion) GetSegmentCount() int {
	if version.IsIPv4() {
		return IPv4SegmentCount
	} else if version.IsIPv6() {
		return IPv6SegmentCount
	}
	return 0
}

// GetMaxSegmentValue returns the maximum possible segment value for this IP version, determined by the number of bits per segment.
func (version IPVersion) GetMaxSegmentValue() SegInt {
	if version.IsIPv4() {
		return IPv4MaxValuePerSegment
	} else if version.IsIPv6() {
		return IPv6MaxValuePerSegment
	}
	return 0
}

// GetBitsPerSegment returns the number of bits comprising each segment for this address version, either 8 or 16 for IPv4 and IPv6 respectively.  Segments in the same address are equal length.
func (version IPVersion) GetBitsPerSegment() BitCount {
	if version.IsIPv4() {
		return IPv4BitsPerSegment
	} else if version.IsIPv6() {
		return IPv6BitsPerSegment
	}
	return 0
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this address or subnet.  Segments in the same address are equal length.
func (version IPVersion) GetBytesPerSegment() int {
	if version.IsIPv4() {
		return IPv4BytesPerSegment
	} else if version.IsIPv6() {
		return IPv6BytesPerSegment
	}
	return 0
}

// index returns an index starting from 0 with IndeterminateIPVersion being the highest
func (version IPVersion) index() int {
	if version.IsIPv4() {
		return 0
	} else if version.IsIPv6() {
		return 1
	}
	return 2
}

func (version IPVersion) toType() (t addrType) {
	if version.IsIPv6() {
		t = ipv6Type
	} else if version.IsIPv4() {
		t = ipv4Type
	}
	return
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
