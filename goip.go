package goip

import (
	"math/big"
	"net"
	"net/netip"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

const (
	// IndeterminateIPVersion represents an unspecified IP address version
	IndeterminateIPVersion IPVersion = 0
	// IPv4 represents Internet Protocol version 4
	IPv4 IPVersion = 4
	// IPv6 represents Internet Protocol version 6
	IPv6                  IPVersion = 6
	PrefixLenSeparator              = '/'
	PrefixLenSeparatorStr           = "/"
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

// Wrap wraps this IP address, returning a WrappedIPAddress, an implementation of ExtendedIPSegmentSeries,
// which can be used to write code that works with both IP addresses and IP address sections.
// Wrap can be called with a nil receiver, wrapping a nil address.
func (addr *IPAddress) Wrap() WrappedIPAddress {
	return wrapIPAddress(addr)
}

// WrapAddress wraps this IP address, returning a WrappedAddress, an implementation of ExtendedSegmentSeries,
// which can be used to write code that works with both addresses and address sections.
// WrapAddress can be called with a nil receiver, wrapping a nil address.
func (addr *IPAddress) WrapAddress() WrappedAddress {
	return wrapAddress(addr.ToAddressBase())
}

func (addr *IPAddress) getLowestHighestAddrs() (lower, upper *IPAddress) {
	l, u := addr.ipAddressInternal.getLowestHighestAddrs()
	return l.ToIP(), u.ToIP()
}

// GetNetIPAddr returns the lowest address in this subnet or address as a net.IPAddr.
func (addr *IPAddress) GetNetIPAddr() *net.IPAddr {
	return &net.IPAddr{
		IP:   addr.GetNetIP(),
		Zone: string(addr.zone),
	}
}

// GetNetworkSection returns an address section containing the segments with the network of the address or subnet, the prefix bits.
// The returned section will have only as many segments as needed as determined by the existing CIDR network prefix length.
//
// If this series has no CIDR prefix length, the returned network section will
// be the entire series as a prefixed section with prefix length matching the address bit length.
func (addr *IPAddress) GetNetworkSection() *IPAddressSection {
	return addr.GetSection().GetNetworkSection()
}

// GetNetworkSectionLen returns a section containing the segments with the network of the address or subnet,
// the prefix bits according to the given prefix length.
// The returned section will have only as many segments as needed to contain the network.
//
// The new section will be assigned the given prefix length,
// unless the existing prefix length is smaller, in which case the existing prefix length will be retained.
func (addr *IPAddress) GetNetworkSectionLen(prefLen BitCount) *IPAddressSection {
	return addr.GetSection().GetNetworkSectionLen(prefLen)
}

// GetHostSection returns a section containing the segments with the host of the address or subnet,
// the bits beyond the CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
//
// If this series has no prefix length, the returned host section will be the full section.
func (addr *IPAddress) GetHostSection() *IPAddressSection {
	return addr.GetSection().GetHostSection()
}

// GetHostSectionLen returns a section containing the segments with the host of the address or subnet,
// the bits beyond the given CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
func (addr *IPAddress) GetHostSectionLen(prefLen BitCount) *IPAddressSection {
	return addr.GetSection().GetHostSectionLen(prefLen)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (addr *IPAddress) CopySubSegments(start, end int, segs []*IPAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (addr *IPAddress) CopySegments(segs []*IPAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this section.
func (addr *IPAddress) GetSegments() []*IPAddressSegment {
	return addr.GetSection().GetSegments()
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0,
// calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (addr *IPAddress) ForEachSegment(consumer func(segmentIndex int, segment *IPAddressSegment) (stop bool)) int {
	return addr.GetSection().ForEachSegment(consumer)
}

// WithoutPrefixLen provides the same address but with no prefix length.
// The values remain unchanged.
func (addr *IPAddress) WithoutPrefixLen() *IPAddress {
	if !addr.IsPrefixed() {
		return addr
	}
	return addr.withoutPrefixLen().ToIP()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (addr *IPAddress) SetPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.init().setPrefixLen(prefixLen).ToIP()
}

// SetPrefixLenZeroed sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
//
// If this address has a prefix length, and the prefix length is increased when setting the new prefix length, the bits moved within the prefix become zero.
// If this address has a prefix length, and the prefix length is decreased when setting the new prefix length, the bits moved outside the prefix become zero.
//
// In other words, bits that move from one side of the prefix length to the other (bits moved into the prefix or outside the prefix) are zeroed.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr *IPAddress) SetPrefixLenZeroed(prefixLen BitCount) (*IPAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIP(), err
}

// AssignMinPrefixForBlock returns an equivalent subnet, assigned the smallest prefix length possible,
// such that the prefix block for that prefix length is in this subnet.
//
// In other words, this method assigns a prefix length to this subnet matching the largest prefix block in this subnet.
//
// Examples:
//   - 1.2.3.4 returns 1.2.3.4/32
//   - 1.2.*.* returns 1.2.0.0/16
//   - 1.2.*.0/24 returns 1.2.0.0/16
//   - 1.2.*.4 returns 1.2.*.4/32
//   - 1.2.0-1.* returns 1.2.0.0/23
//   - 1.2.1-2.* returns 1.2.1-2.0/24
//   - 1.2.252-255.* returns 1.2.252.0/22
//   - 1.2.3.4/16 returns 1.2.3.4/32
func (addr *IPAddress) AssignMinPrefixForBlock() *IPAddress {
	return addr.init().assignMinPrefixForBlock().ToIP()
}

// GetValue returns the lowest address in this subnet or address as an integer value.
func (addr *IPAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

// GetUpperValue returns the highest address in this subnet or address as an integer value.
func (addr *IPAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

// CopyBytes copies the value of the lowest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPAddress) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

// CopyUpperBytes copies the value of the highest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPAddress) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

// IsMax returns whether this address matches exactly the maximum possible value,
// the address whose bits are all ones.
func (addr *IPAddress) IsMax() bool {
	return addr.init().section.IsMax()
}

// IncludesMax returns whether this address includes the max address,
// the address whose bits are all ones, within its range.
func (addr *IPAddress) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// TestBit returns true if the bit in the lower value of this address at the given index is 1,
// where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this address.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (addr *IPAddress) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// IsOneBit returns true if the bit in the lower value of this address at the given index is 1,
// where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (addr *IPAddress) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (addr *IPAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

// Iterator provides an iterator to iterate through the individual addresses of this address or subnet.
//
// When iterating, the prefix length is preserved.
// Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual addresses.
//
// Call IsMultiple to determine if this instance represents multiple addresses, or GetCount for the count.
func (addr *IPAddress) Iterator() Iterator[*IPAddress] {
	if addr == nil {
		return ipAddrIterator{nilAddrIterator()}
	}
	return ipAddrIterator{addr.init().addrIterator(nil)}
}

// BlockIterator iterates through the addresses that can be obtained by iterating through all the upper segments up to the given segment count.
// The segments following remain the same in all iterated addresses.
//
// For instance, given the IPv4 subnet "1-2.3-4.5-6.7" and the count argument 2,
// BlockIterator will iterate through "1.3.5-6.7", "1.4.5-6.7", "2.3.5-6.7" and "2.4.5-6.7".
func (addr *IPAddress) BlockIterator(segmentCount int) Iterator[*IPAddress] {
	return ipAddrIterator{addr.init().blockIterator(segmentCount)}
}

// SequentialBlockIterator iterates through the sequential subnets or addresses that make up this address or subnet.
//
// Practically, this means finding the count of segments for which the segments that follow are not full range,
// and then using BlockIterator with that segment count.
//
// For instance, given the IPv4 subnet "1-2.3-4.5-6.7-8",
// it will iterate through "1.3.5.7-8", "1.3.6.7-8", "1.4.5.7-8", "1.4.6.7-8", "2.3.5.7-8", "2.3.6.7-8", "2.4.6.7-8" and "2.4.6.7-8".
//
// Use GetSequentialBlockCount to get the number of iterated elements.
func (addr *IPAddress) SequentialBlockIterator() Iterator[*IPAddress] {
	return ipAddrIterator{addr.init().sequentialBlockIterator()}
}

// GetSequentialBlockIndex gets the minimal segment index for which all following segments are full-range blocks.
//
// The segment at this index is not a full-range block itself, unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full subnet to be sequential, the preceding segments must be single-valued.
func (addr *IPAddress) GetSequentialBlockIndex() int {
	return addr.getSequentialBlockIndex()
}

// GetSequentialBlockCount provides the count of elements from the sequential block iterator,
// the minimal number of sequential subnets that comprise this subnet.
func (addr *IPAddress) GetSequentialBlockCount() *big.Int {
	return addr.getSequentialBlockCount()
}

// IsUnspecified returns true if exactly zero.  The unspecified address is the address that is all zeros.
func (addr *IPAddress) IsUnspecified() bool {
	return addr.section != nil && addr.IsZero()
}

// IsAnyLocal returns whether this address is the address which binds to any address on the local host.
// This is the address that has the value of 0, aka the unspecified address.
func (addr *IPAddress) IsAnyLocal() bool {
	return addr.section != nil && addr.IsZero()
}

// IsMulticast returns whether this address or subnet is entirely multicast.
func (addr *IPAddress) IsMulticast() bool {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		return thisAddr.IsMulticast()
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		return thisAddr.IsMulticast()
	}
	return false
}

// ReverseSegments returns a new address with the segments reversed.
func (addr *IPAddress) ReverseSegments() *IPAddress {
	return addr.init().reverseSegments().ToIP()
}

// GetSegmentStrings returns a slice with the string for
// each segment being the string that is normalized with wildcards.
func (addr *IPAddress) GetSegmentStrings() []string {
	if addr == nil {
		return nil
	}
	return addr.init().getSegmentStrings()
}

// GetLeadingBitCount returns the number of consecutive leading one or zero bits.
// If ones is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
//
// This method applies to the lower value of the range if this is a subnet representing multiple values.
func (addr *IPAddress) GetLeadingBitCount(ones bool) BitCount {
	return addr.init().getLeadingBitCount(ones)
}

// GetTrailingBitCount returns the number of consecutive trailing one or zero bits.
// If ones is true, returns the number of consecutive trailing zero bits.
// Otherwise, returns the number of consecutive trailing one bits.
//
// This method applies to the lower value of the range if this is a subnet representing multiple values.
func (addr *IPAddress) GetTrailingBitCount(ones bool) BitCount {
	return addr.init().getTrailingBitCount(ones)
}

func (addr *IPAddress) toMaxLower() *IPAddress {
	return addr.init().addressInternal.toMaxLower().ToIP()
}

func (addr *IPAddress) toMinUpper() *IPAddress {
	return addr.init().addressInternal.toMinUpper().ToIP()
}

// GetNetworkMask returns the network mask associated with the CIDR network prefix length of this address or subnet.
// If this address or subnet has no prefix length, then the all-ones mask is returned.
func (addr *IPAddress) GetNetworkMask() *IPAddress {
	return addr.getNetworkMask(addr.getNetwork())
}

// GetHostMask returns the host mask associated with the CIDR network prefix length of this address or subnet.
// If this address or subnet has no prefix length, then the all-ones mask is returned.
func (addr *IPAddress) GetHostMask() *IPAddress {
	return addr.getHostMask(addr.getNetwork())
}

// IsZeroHostLen returns whether the host section is always zero for all individual addresses in this subnet,
// for the given prefix length.
//
// If the host section is zero length (there are zero host bits), IsZeroHostLen returns true.
func (addr *IPAddress) IsZeroHostLen(prefLen BitCount) bool {
	return addr.init().isZeroHostLen(prefLen)
}

// IsMaxHostLen returns whether the host is all one-bits, the max value, for all individual addresses in this subnet,
// for the given prefix length, the host being the bits following the prefix.
//
// If the host section is zero length (there are zero host bits), IsMaxHostLen returns true.
func (addr *IPAddress) IsMaxHostLen(prefLen BitCount) bool {
	return addr.init().isMaxHostLen(prefLen)
}

// GetNetNetIPAddr returns the lowest address in this subnet or address range as a netip.Addr.
func (addr *IPAddress) GetNetNetIPAddr() netip.Addr {
	res := addr.init().getNetNetIPAddr()
	if addr.hasZone() {
		res = res.WithZone(string(addr.zone))
	}
	return res
}

// GetUpperNetNetIPAddr returns the highest address in this subnet or address range as a netip.Addr.
func (addr *IPAddress) GetUpperNetNetIPAddr() netip.Addr {
	return addr.init().getUpperNetNetIPAddr()
}

// GetIPVersion returns the IP version of this IP address.
func (addr *IPAddress) GetIPVersion() IPVersion {
	if addr == nil {
		return IndeterminateIPVersion
	}
	return addr.getIPVersion()
}

// IncludesZeroHostLen returns whether the subnet contains an individual address with a host of zero,
// an individual address for which all bits past the given prefix length are zero.
func (addr *IPAddress) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

// IncludesMaxHostLen returns whether the subnet contains an individual address with a host of all one-bits,
// an individual address for which all bits past the given prefix length are all ones.
func (addr *IPAddress) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

// GetNetwork returns the singleton network instance for the IP version of this address or subnet.
func (addr *IPAddress) GetNetwork() IPAddressNetwork {
	return addr.getNetwork()
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (addr *IPAddress) GetTrailingSection(index int) *IPAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

// GetSubSection gets the subsection from the series starting from
// the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (addr *IPAddress) GetSubSection(index, endIndex int) *IPAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopyNetIP copies the value of the lowest individual address in the subnet into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPAddress) CopyNetIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4(); ipv4Addr != nil {
		return ipv4Addr.CopyNetIP(ip) // this shrinks the arg to 4 bytes if it was 16, we need only 4
	}
	return addr.CopyBytes(ip)
}

// CopyUpperNetIP copies the value of the highest individual address in the subnet into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPAddress) CopyUpperNetIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4(); ipv4Addr != nil {
		return ipv4Addr.CopyUpperNetIP(ip) // this shrinks the arg to 4 bytes if it was 16, we need only 4
	}
	return addr.CopyUpperBytes(ip)
}

// MatchesWithMask applies the mask to this address and then compares the result with the given address,
// returning true if they match, false otherwise.
func (addr *IPAddress) MatchesWithMask(other *IPAddress, mask *IPAddress) bool {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		if oth := other.ToIPv4(); oth != nil {
			if msk := mask.ToIPv4(); mask != nil {
				return thisAddr.MatchesWithMask(oth, msk)
			}
		}
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		if oth := other.ToIPv6(); oth != nil {
			if msk := mask.ToIPv6(); mask != nil {
				return thisAddr.MatchesWithMask(oth, msk)
			}
		}
	}
	return false
}

// Mask applies the given mask to all addresses represented by this IPAddress.
// The mask is applied to all individual addresses.
//
// If the mask is a different version than this, then an error is returned.
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (addr *IPAddress) Mask(other *IPAddress) (masked *IPAddress, err address_error.IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

func (addr *IPAddress) maskPrefixed(other *IPAddress, retainPrefix bool) (*IPAddress, address_error.IncompatibleAddressError) {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		if oth := other.ToIPv4(); oth != nil {
			result, err := thisAddr.maskPrefixed(oth, retainPrefix)
			return result.ToIP(), err
		}
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		if oth := other.ToIPv6(); oth != nil {
			result, err := thisAddr.maskPrefixed(oth, retainPrefix)
			return result.ToIP(), err
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
}

// IsLinkLocal returns whether the address or subnet is entirely link local, whether unicast or multicast.
func (addr *IPAddress) IsLinkLocal() bool {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		return thisAddr.IsLinkLocal()
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		return thisAddr.IsLinkLocal()
	}
	return false
}

// IsLocal returns true if the address is link local, site local,
// organization local, administered locally, or unspecified.
// This includes both unicast and multicast.
func (addr *IPAddress) IsLocal() bool {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		return thisAddr.IsLocal()
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		return thisAddr.IsLocal()
	}
	return false
}

// IsLoopback returns whether this address is a loopback address,
// such as "::1" or "127.0.0.1".
func (addr *IPAddress) IsLoopback() bool {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		return thisAddr.IsLoopback()
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		return thisAddr.IsLoopback()
	}
	return false
}

// ReverseBytes returns a new address with the bytes reversed.  Any prefix length is dropped.
//
// If each segment is more than 1 byte long,
// and the bytes within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, then this returns an error.
//
// In practice this means that to be reversible,
// a segment range must include all values except possibly the largest and/or smallest, which reverse to themselves.
func (addr *IPAddress) ReverseBytes() (*IPAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().reverseBytes()
	return res.ToIP(), err
}

// ReverseBits returns a new address with the bits reversed.  Any prefix length is dropped.
//
// If the bits within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, this returns an error.
//
// In practice this means that to be reversible,
// a segment range must include all values except possibly the largest and/or smallest, which reverse to themselves.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (addr *IPAddress) ReverseBits(perByte bool) (*IPAddress, address_error.IncompatibleAddressError) {
	res, err := addr.init().reverseBits(perByte)
	return res.ToIP(), err
}

// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this address.
// The returned block will have an assigned prefix length indicating the prefix length for the block.
//
// There may be no such address - it is required that the range of values match the range of a prefix block.
// If there is no such address, then nil is returned.
//
// Examples:
//   - 1.2.3.4 returns 1.2.3.4/32
//   - 1.2.*.* returns 1.2.0.0/16
//   - 1.2.*.0/24 returns 1.2.0.0/16
//   - 1.2.*.4 returns nil
//   - 1.2.0-1.* returns 1.2.0.0/23
//   - 1.2.1-2.* returns nil
//   - 1.2.252-255.* returns 1.2.252.0/22
//   - 1.2.3.4/16 returns 1.2.3.4/32
func (addr *IPAddress) AssignPrefixForSingleBlock() *IPAddress {
	return addr.init().assignPrefixForSingleBlock().ToIP()
}

// ToSinglePrefixBlockOrAddress converts to a single prefix block or address.
// If the given address is a single prefix block, it is returned.
// If it can be converted to a single prefix block by assigning a prefix length,
// the converted block is returned.
// If it is a single address, any prefix length is removed and the address is returned.
// Otherwise, nil is returned.
// This method provides the address formats used by tries.
// ToSinglePrefixBlockOrAddress is quite similar to AssignPrefixForSingleBlock,
// which always returns prefixed addresses, while this does not.
func (addr *IPAddress) ToSinglePrefixBlockOrAddress() *IPAddress {
	return addr.init().toSinglePrefixBlockOrAddr().ToIP()
}

func (addr *IPAddress) toSinglePrefixBlockOrAddress() (*IPAddress, address_error.IncompatibleAddressError) {
	if addr == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.address.not.block"}}
	}

	res := addr.ToSinglePrefixBlockOrAddress()
	if res == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.address.not.block"}}
	}

	return res, nil
}

// BitwiseOr does the bitwise disjunction with this address or subnet, useful when subnetting.
// It is similar to Mask which does the bitwise conjunction.
//
// The operation is applied to all individual addresses and the result is returned.
//
// If the given address is a different version than this, then an error is returned.
//
// If this is a subnet representing multiple addresses, and applying the operations to all addresses creates a set of addresses
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (addr *IPAddress) BitwiseOr(other *IPAddress) (masked *IPAddress, err address_error.IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, true)
}

func (addr *IPAddress) bitwiseOrPrefixed(other *IPAddress, retainPrefix bool) (*IPAddress, address_error.IncompatibleAddressError) {
	if thisAddr := addr.ToIPv4(); thisAddr != nil {
		if oth := other.ToIPv4(); oth != nil {
			result, err := thisAddr.bitwiseOrPrefixed(oth, retainPrefix)
			return result.ToIP(), err
		}
	} else if thisAddr := addr.ToIPv6(); thisAddr != nil {
		if oth := other.ToIPv6(); oth != nil {
			result, err := thisAddr.bitwiseOrPrefixed(oth, retainPrefix)
			return result.ToIP(), err
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
}

// IPVersion is the version type used by IP address types.
type IPVersion int

// IsIPv4 returns true if this represents version 4.
func (version IPVersion) IsIPv4() bool {
	return version == IPv4
}

// IsIPv6 returns true if this represents version 6.
func (version IPVersion) IsIPv6() bool {
	return version == IPv6
}

// IsIndeterminate returns true if this represents an unspecified IP address version
func (version IPVersion) IsIndeterminate() bool {
	return version != IPv4 && version != IPv6
}

// Equal returns true if the given version matches this version.
// Two indeterminate versions always match, even if their associated strings do not.
func (version IPVersion) Equal(other IPVersion) bool {
	switch version {
	case IPv4, IPv6:
		return version == other
	default:
		return other != IPv4 && other != IPv6
	}
}

// String returns "IPv4", "IPv6" or the nil-value ("") representing an indeterminate version.
func (version IPVersion) String() string {
	switch version {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return ""
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

func (version IPVersion) GetNetwork() (network IPAddressNetwork) {
	if version.IsIPv6() {
		network = ipv6Network
	} else if version.IsIPv4() {
		network = ipv4Network
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

func (addr *ipAddressInternal) getIPVersion() IPVersion {
	if addr.isIPv4() {
		return IPv4
	} else if addr.isIPv6() {
		return IPv6
	}
	return IndeterminateIPVersion
}

func (addr *ipAddressInternal) getNetworkPrefixLen() PrefixLen {
	section := addr.section
	if section == nil {
		return nil
	}
	return section.ToIP().getNetworkPrefixLen()
}

// GetNetworkPrefixLen returns the prefix length, or nil if there is no prefix length.
// GetNetworkPrefixLen is equivalent to the method GetPrefixLen.
func (addr *ipAddressInternal) GetNetworkPrefixLen() PrefixLen {
	return addr.getNetworkPrefixLen().copy()
}

func (addr *ipAddressInternal) getNetNetIPAddr() netip.Addr {
	netAddr, _ := netip.AddrFromSlice(addr.getBytes())
	return netAddr
}

func (addr *ipAddressInternal) getUpperNetNetIPAddr() netip.Addr {
	netAddr, _ := netip.AddrFromSlice(addr.getUpperBytes())
	return netAddr
}

func (addr *ipAddressInternal) getSection() *IPAddressSection {
	return addr.section.ToIP()
}

// IncludesZeroHost returns whether the subnet contains an individual address with a host of zero.
// If the subnet has no prefix length it returns false.
// If the prefix length matches the bit count, then it returns true.
//
// Otherwise, it checks whether it contains an individual address for which all bits past the prefix are zero.
func (addr *ipAddressInternal) IncludesZeroHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIP().IncludesZeroHost()
}

// IncludesMaxHost returns whether the subnet contains an individual address with a host of all one-bits.
// If the subnet has no prefix length it returns false.
// If the prefix length matches the bit count, then it returns true.
//
// Otherwise, it checks whether it contains an individual address for which all bits past the prefix are one.
func (addr *ipAddressInternal) IncludesMaxHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIP().IncludesMaxHost()
}

func (addr *ipAddressInternal) includesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesZeroHostLen(networkPrefixLength)
}

func (addr *ipAddressInternal) includesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesMaxHostLen(networkPrefixLength)
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value.
//
// If it has no prefix length, it returns true if not multiple,
// if it contains only a single individual address.
func (addr *ipAddressInternal) IsSingleNetwork() bool {
	section := addr.section
	return section == nil || section.ToIP().IsSingleNetwork()
}

// IsMaxHost returns whether this section has a prefix length and if so,
// whether the host section is always all one-bits, the max value,
// for all individual addresses in this subnet.
//
// If the host section is zero length (there are zero host bits), IsMaxHost returns true.
func (addr *ipAddressInternal) IsMaxHost() bool {
	section := addr.section
	return section != nil && section.ToIP().IsMaxHost()
}

// IsMaxHostLen returns whether the host section is always one-bits,
// the max value, for all individual addresses in this subnet,
// for the given prefix length.
//
// If the host section is zero length (there are zero host bits), IsMaxHostLen returns true.
func (addr *ipAddressInternal) isMaxHostLen(prefLen BitCount) bool {
	return addr.getSection().IsMaxHostLen(prefLen)
}

// IsZeroHost returns whether this subnet has a prefix length and if so,
// whether the host section is always zero for all individual addresses in this subnet.
//
// If the host section is zero length (there are zero host bits), IsZeroHost returns true.
func (addr *ipAddressInternal) IsZeroHost() bool {
	section := addr.section
	return section != nil && section.ToIP().IsZeroHost()
}

// IsZeroHostLen returns whether the host section is always zero for all individual sections in this address section,
// for the given prefix length.
//
// If the host section is zero length (there are zero host bits), IsZeroHostLen returns true.
func (addr *ipAddressInternal) isZeroHostLen(prefLen BitCount) bool {
	return addr.getSection().IsZeroHostLen(prefLen)
}

func (addr *ipAddressInternal) checkIdentity(section *IPAddressSection) *IPAddress {
	if section == nil {
		return nil
	}
	sect := section.ToSectionBase()
	if sect == addr.section {
		return addr.toIPAddress()
	}
	return createIPAddress(sect, addr.zone)
}

func (addr *ipAddressInternal) adjustPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.checkIdentity(addr.getSection().adjustPrefixLen(prefixLen))
}

func (addr *ipAddressInternal) adjustPrefixLenZeroed(prefixLen BitCount) (res *IPAddress, err address_error.IncompatibleAddressError) {
	section, err := addr.getSection().adjustPrefixLenZeroed(prefixLen)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) getNetworkMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if pref := addr.getPrefixLen(); pref != nil {
		prefLen = pref.bitCount()
	} else {
		prefLen = addr.GetBitCount()
	}
	return network.GetNetworkMask(prefLen)
}

func (addr *ipAddressInternal) getHostMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.isPrefixed() {
		prefLen = addr.getNetworkPrefixLen().bitCount()
	}
	return network.GetHostMask(prefLen)
}

func (addr *ipAddressInternal) getNetwork() IPAddressNetwork {
	return addr.getSection().getNetwork()
}

// IsPrefixBlock returns whether the address has a prefix length and
// the address range includes the block of values for that prefix length.
// If the prefix length matches the bit count, this returns true.
//
// To create a prefix block from any address, use ToPrefixBlock.
//
// This is different from ContainsPrefixBlock in that this method returns
// false if the series has no prefix length, or a prefix length that differs from
// a prefix length for which ContainsPrefixBlock returns true.
func (addr *ipAddressInternal) IsPrefixBlock() bool {
	return addr.addressInternal.IsPrefixBlock()
}

// ContainsPrefixBlock returns whether the range of this address or subnet contains
// the block of addresses for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in
// this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length
// for which this method returns true.
func (addr *ipAddressInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.addressInternal.ContainsPrefixBlock(prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that
// this includes the block of addresses for that prefix length.
//
// If the entire range can be described this way,
// then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in
// this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this represents just a single address,
// returns the bit length of this address.
//
// See AssignMinPrefixForBlock for some examples.
func (addr *ipAddressInternal) GetMinPrefixLenForBlock() BitCount {
	return addr.addressInternal.GetMinPrefixLenForBlock()
}

// When boundariesOnly is true, there will be no error.
func (addr *ipAddressInternal) toZeroHost(boundariesOnly bool) (res *IPAddress, err address_error.IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toZeroHost(boundariesOnly)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toZeroHostLen(prefixLength BitCount) (res *IPAddress, err address_error.IncompatibleAddressError) {
	section, err := addr.getSection().toZeroHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toZeroNetwork() *IPAddress {
	return addr.checkIdentity(addr.getSection().toZeroNetwork())
}

func (addr *ipAddressInternal) toMaxHost() (res *IPAddress, err address_error.IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toMaxHost()
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toMaxHostLen(prefixLength BitCount) (res *IPAddress, err address_error.IncompatibleAddressError) {
	section, err := addr.getSection().toMaxHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

// IPAddressValueProvider supplies all the values that incorporate an IPAddress instance.
type IPAddressValueProvider interface {
	AddressValueProvider
	GetPrefixLen() PrefixLen // return nil if none
	GetIPVersion() IPVersion // should not return IndeterminateVersion
	GetZone() string         // return "" or NoZone if none
}

// IPAddressCreator is a polymporphic type providing constructor methods to
// construct IP addresses corresponding to its contained IP version
type IPAddressCreator struct {
	IPVersion
}

// CreateSegment creates an IPv4 or IPv6 segment depending on the IP version assigned to this IPAddressCreator instance.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) CreateSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangePrefixedSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6RangePrefixedSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToIP()
	}
	return nil
}

// CreateRangeSegment creates an IPv4 or IPv6 range-valued segment depending on the IP version assigned to this IPAddressCreator instance.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) CreateRangeSegment(lower, upper SegInt) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangeSegment(IPv4SegInt(lower), IPv4SegInt(upper)).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6RangeSegment(IPv6SegInt(lower), IPv6SegInt(upper)).ToIP()
	}
	return nil
}

// CreatePrefixSegment creates an IPv4 or IPv6 segment with a prefix length depending on the IP version assigned to this IPAddressCreator instance.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) CreatePrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4PrefixedSegment(IPv4SegInt(value), segmentPrefixLength).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6PrefixedSegment(IPv6SegInt(value), segmentPrefixLength).ToIP()
	}
	return nil
}

// NewIPSectionFromBytes creates an address section from the given bytes,
// It is IPv4 or IPv6 depending on the IP version assigned to this IPAddressCreator instance.
// The number of segments is determined by the length of the byte array.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) NewIPSectionFromBytes(bytes []byte) *IPAddressSection {
	if creator.IsIPv4() {
		return NewIPv4SectionFromBytes(bytes).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6SectionFromBytes(bytes).ToIP()
	}
	return nil
}

// NewIPSectionFromSegmentedBytes creates an address section from the given bytes.  It is IPv4 or IPv6 depending on the IP version assigned to this IPAddressCreator instance.
// The number of segments is given.  An error is returned when the byte slice has too many bytes to match the segment count.
// IPv4 should have 4 bytes or less, IPv6 16 bytes or less, although extra leading zeros are tolerated.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) NewIPSectionFromSegmentedBytes(bytes []byte, segmentCount int) (*IPAddressSection, address_error.AddressValueError) {
	if creator.IsIPv4() {
		addr, err := NewIPv4SectionFromSegmentedBytes(bytes, segmentCount)
		return addr.ToIP(), err
	} else if creator.IsIPv6() {
		addr, err := NewIPv6SectionFromSegmentedBytes(bytes, segmentCount)
		return addr.ToIP(), err
	}
	return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.ipVersionIndeterminate"}}
}

// NewIPSectionFromPrefixedBytes creates an address section from the given bytes and prefix length.  It is IPv4 or IPv6 depending on the IP version assigned to this IPAddressCreator instance.
// The number of segments is given.  An error is returned when the byte slice has too many bytes to match the segment count.
// IPv4 should have 4 bytes or less, IPv6 16 bytes or less, although extra leading zeros are tolerated.
// If the IP version is indeterminate, then nil is returned.
func (creator IPAddressCreator) NewIPSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefLen PrefixLen) (*IPAddressSection, address_error.AddressValueError) {
	if creator.IsIPv4() {
		addr, err := NewIPv4SectionFromPrefixedBytes(bytes, segmentCount, prefLen)
		return addr.ToIP(), err
	} else if creator.IsIPv6() {
		addr, err := NewIPv4SectionFromPrefixedBytes(bytes, segmentCount, prefLen)
		return addr.ToIP(), err
	}
	return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.ipVersionIndeterminate"}}
}

// NewIPAddressFromVals constructs an IPAddress from the provided segment values.
// If the IP version of this IPAddressCreator is indeterminate, then nil is returned.
func (creator IPAddressCreator) NewIPAddressFromVals(lowerValueProvider SegmentValueProvider) *IPAddress {
	return NewIPAddressFromVals(creator.IPVersion, lowerValueProvider)
}

// NewIPAddressFromPrefixedVals constructs an IPAddress from the provided segment values and prefix length.
// If the IP version of this IPAddressCreator is indeterminate, then nil is returned.
// The prefix length is adjusted to 0 if negative or to the bit count if larger.
func (creator IPAddressCreator) NewIPAddressFromPrefixedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return NewIPAddressFromPrefixedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength)
}

// NewIPAddressFromPrefixedZonedVals constructs an IPAddress from the provided segment values, prefix length, and zone.
// If the IP version of this IPAddressCreator is indeterminate, then nil is returned.
// If the version is IPv4, then the zone is ignored.
// The prefix length is adjusted to 0 if negative or to the bit count if larger.
func (creator IPAddressCreator) NewIPAddressFromPrefixedZonedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	return NewIPAddressFromPrefixedZonedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength, zone)
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

func versionsMatch(one, two *IPAddress) bool {
	return one.getAddrType() == two.getAddrType()
}

func newIPAddressZoned(section *IPAddressSection, zone Zone) *IPAddress {
	result := createIPAddress(section.ToSectionBase(), zone)
	if zone != NoZone {
		result.cache.stringCache = &stringCache{}
	}
	return result
}

func isAllZeros(byts []byte) bool {
	for _, b := range byts {
		if b != 0 {
			return false
		}
	}
	return true
}

func addrFromIP(ip net.IP) (addr *IPAddress, err address_error.AddressValueError) {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return addrFromBytes(ip)
}

func addrFromBytes(ip []byte) (addr *IPAddress, err address_error.AddressValueError) {
	addrLen := len(ip)
	if len(ip) == 0 {
		return &IPAddress{}, nil
	} else if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromBytes(ip)
		addr = addr4.ToIP()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromBytes(ip)
		addr = addr6.ToIP()
	} else {
		extraCount := len(ip) - IPv6ByteCount
		if isAllZeros(ip[:extraCount]) {
			var addr6 *IPv6Address
			addr6, err = NewIPv6AddressFromBytes(ip[extraCount:])
			addr = addr6.ToIP()
		} else {
			err = &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
		}
	}
	return
}

func addrFromZonedIP(addr *net.IPAddr) (*IPAddress, address_error.AddressValueError) {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	if len(ip) == 0 {
		return &IPAddress{}, nil
	} else if len(ip) <= IPv4ByteCount {
		res, err := NewIPv4AddressFromBytes(ip)
		return res.ToIP(), err
	} else if len(ip) <= IPv6ByteCount {
		res, err := NewIPv6AddressFromZonedBytes(ip, addr.Zone)
		return res.ToIP(), err
	} else {
		extraCount := len(ip) - IPv6ByteCount
		if isAllZeros(ip[:extraCount]) {
			var addr6 *IPv6Address
			addr6, err := NewIPv6AddressFromZonedBytes(ip[extraCount:], addr.Zone)
			res := addr6.ToIP()
			return res, err
		}
	}

	return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
}

// NewIPAddressFromNetIPMask constructs an address from a net.IPMask.
// An error is returned when the mask has an invalid number of bytes.
// IPv4 should have 4 bytes or less, IPv6 16 bytes or less,
// although extra leading zeros are tolerated.
func NewIPAddressFromNetIPMask(ip net.IPMask) (*IPAddress, address_error.AddressValueError) {
	return addrFromBytes(ip)
}

// NewIPAddressFromBytes constructs an address from a slice of bytes.
// An error is returned when the IP has an invalid number of bytes.
// IPv4 should have 4 bytes or less, IPv6 16 bytes or less, although extra leading zeros are tolerated.
func NewIPAddressFromBytes(ip net.IP) (*IPAddress, address_error.AddressValueError) {
	return addrFromBytes(ip)
}

// NewIPAddressFromNetIP constructs an address from a net.IP.
// An error is returned when the IP has an invalid number of bytes.
// IPv4 should have 4 bytes or less, IPv6 16 bytes or less, although extra leading zeros are tolerated.
func NewIPAddressFromNetIP(ip net.IP) (*IPAddress, address_error.AddressValueError) {
	return addrFromIP(ip)
}

// NewIPAddressFromNetIPAddr constructs an address or subnet from a net.IPAddr.
// An error is returned when the IP has an invalid number of bytes.  IPv4 should have 4 bytes or less, IPv6 16 bytes or less, although extra leading zeros are tolerated.
func NewIPAddressFromNetIPAddr(addr *net.IPAddr) (*IPAddress, address_error.AddressValueError) {
	return addrFromZonedIP(addr)
}

// NewIPAddressFromNetIPNet constructs a subnet from a net.IPNet.
// The error can be either address_error.AddressValueError, when the net.IPNet IP or mask has an invalid number of bytes,
// or address_error.IncompatibleAddressError when the mask and the IP from net.IPNet are different IP versions.
func NewIPAddressFromNetIPNet(ipnet *net.IPNet) (*IPAddress, address_error.AddressError) {
	ip := ipnet.IP
	maskIp := ipnet.Mask
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		if len(maskIp) == net.IPv6len {
			maskIp = maskIp[IPv6MixedOriginalByteCount:]
		}
	}

	addr, err := addrFromBytes(ip)
	if err != nil {
		return nil, err
	} else if addr == nil {
		return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
	}

	mask, err := NewIPAddressFromNetIPMask(maskIp)
	if err != nil {
		return nil, err
	} else if mask == nil {
		return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
	} else if addr.getAddrType() != mask.getAddrType() {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
	}

	prefLen := mask.GetBlockMaskPrefixLen(true)
	if prefLen == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.notNetworkMask"}}
	}

	return addr.ToPrefixBlockLen(prefLen.bitCount()), nil
}

// NewIPAddressFromPrefixedSegments constructs an address from the given segments and prefix length.
// If the segments are not consistently IPv4 or IPv6, or if there is not the correct number of segments for the IP version (4 for IPv4, 8 for IPv6),
// then an error is returned.
func NewIPAddressFromPrefixedSegments(segs []*IPAddressSegment, prefixLength PrefixLen) (res *IPAddress, err address_error.AddressValueError) {
	if len(segs) > 0 {
		if segs[0].IsIPv4() {
			for _, seg := range segs[1:] {
				if !seg.IsIPv4() {
					err = &addressValueError{addressError: addressError{key: "ipaddress.error.ipVersionMismatch"}}
					return
				}
			}
			sect := createIPSectionFromSegs(true, segs, prefixLength)
			addr, address_Error := NewIPv4Address(sect.ToIPv4())
			res, err = addr.ToIP(), address_Error
		} else if segs[0].IsIPv6() {
			for _, seg := range segs[1:] {
				if !seg.IsIPv6() {
					err = &addressValueError{addressError: addressError{key: "ipaddress.error.ipVersionMismatch"}}
					return
				}
			}
			sect := createIPSectionFromSegs(false, segs, prefixLength)
			addr, address_Error := NewIPv6Address(sect.ToIPv6())
			res, err = addr.ToIP(), address_Error
		} else {
			err = &addressValueError{addressError: addressError{key: "ipaddress.error.invalid.size"}}
		}
	} else {
		err = &addressValueError{addressError: addressError{key: "ipaddress.error.invalid.size"}}
	}
	return
}

func NewIPAddressFromNetNetIPAddr(addr netip.Addr) *IPAddress {
	if res := addr.AsSlice(); res != nil {
		if addr.Is6() {
			if zone := addr.Zone(); zone != "" {
				addr, _ := NewIPv6AddressFromZonedBytes(res, zone)
				return addr.ToIP()
			}
		}
		addr, _ := addrFromBytes(res)
		return addr.ToIP()
	}
	// the zero addr
	return &IPAddress{}
}

// NewIPAddressFromSegs constructs an address from the given segments.
// If the segments are not consistently IPv4 or IPv6,
// or if there is not the correct number of segments for the IP version (4 for IPv4, 8 for IPv6),
// then an error is returned.
func NewIPAddressFromSegs(segments []*IPAddressSegment) (res *IPAddress, err address_error.AddressValueError) {
	return NewIPAddressFromPrefixedSegments(segments, nil)
}

func addrFromPrefixedZonedIP(addr *net.IPAddr, prefixLen PrefixLen) (*IPAddress, address_error.AddressValueError) {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	if len(ip) == 0 {
		return &IPAddress{}, nil
	} else if len(ip) <= IPv4ByteCount {
		res, err := NewIPv4AddressFromPrefixedBytes(ip, prefixLen)
		return res.ToIP(), err
	} else if len(ip) <= IPv6ByteCount {
		res, err := NewIPv6AddressFromPrefixedZonedBytes(ip, prefixLen, addr.Zone)
		return res.ToIP(), err
	} else {
		extraCount := len(ip) - IPv6ByteCount
		if isAllZeros(ip[:extraCount]) {
			var addr6 *IPv6Address
			addr6, err := NewIPv6AddressFromPrefixedZonedBytes(ip[extraCount:], prefixLen, addr.Zone)
			res := addr6.ToIP()
			return res, err
		}
	}
	return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
}

func addrFromPrefixedBytes(ip []byte, prefixLen PrefixLen) (addr *IPAddress, err address_error.AddressValueError) {
	addrLen := len(ip)
	if len(ip) == 0 {
		return &IPAddress{}, nil
	} else if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromPrefixedBytes(ip, prefixLen)
		addr = addr4.ToIP()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromPrefixedBytes(ip, prefixLen)
		addr = addr6.ToIP()
	} else {
		extraCount := len(ip) - IPv6ByteCount
		if isAllZeros(ip[:extraCount]) {
			var addr6 *IPv6Address
			addr6, err = NewIPv6AddressFromPrefixedBytes(ip[extraCount:], prefixLen)
			addr = addr6.ToIP()
		} else {
			err = &addressValueError{addressError: addressError{key: "ipaddress.error.exceeds.size"}}
		}
	}
	return
}

func addrFromPrefixedIP(ip net.IP, prefixLen PrefixLen) (addr *IPAddress, err address_error.AddressValueError) {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return addrFromPrefixedBytes(ip, prefixLen)
}

// NewIPAddressFromPrefixedNetIP constructs an address or subnet from a net.IP with a prefix length.
// An error is returned when the IP has an invalid number of bytes.  IPv4 should have 4 bytes or less,
// IPv6 16 bytes or less, although extra leading zeros are tolerated.
func NewIPAddressFromPrefixedNetIP(ip net.IP, prefixLength PrefixLen) (*IPAddress, address_error.AddressValueError) {
	return addrFromPrefixedIP(ip, prefixLength)
}

// NewIPAddressFromPrefixedNetIPAddr constructs an address or subnet from a net.IPAddr with a prefix length.
// An error is returned when the IP has an invalid number of bytes.  IPv4 should have 4 bytes or less, IPv6 16 bytes or less,
// although extra leading zeros are tolerated.
func NewIPAddressFromPrefixedNetIPAddr(addr *net.IPAddr, prefixLength PrefixLen) (*IPAddress, address_error.AddressValueError) {
	return addrFromPrefixedZonedIP(addr, prefixLength)
}

func NewIPAddressFromNetNetIPPrefix(prefixedAddr netip.Prefix) (*IPAddress, address_error.AddressError) {
	prefixLen := prefixedAddr.Bits()
	if prefixLen < 0 {
		return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.invalidCIDRPrefix"}}
	}

	addr := prefixedAddr.Addr()
	if res := addr.AsSlice(); res != nil {
		var p PrefixBitCount = PrefixBitCount(prefixLen)
		if addr.Is6() {
			if zone := addr.Zone(); zone != "" {
				addr, _ := NewIPv6AddressFromPrefixedZonedBytes(res, &p, zone)
				return addr.ToIP(), nil
			}
		}
		addr, _ := addrFromPrefixedBytes(res, &p)
		return addr.ToIP(), nil
	}
	return nil, &addressValueError{addressError: addressError{key: "ipaddress.error.ipVersionIndeterminate"}}
}

// NewIPAddressFromVals constructs an IPAddress from the provided segment values.
// If the given version is indeterminate, then nil is returned.
func NewIPAddressFromVals(version IPVersion, lowerValueProvider SegmentValueProvider) *IPAddress {
	if version.IsIPv4() {
		return NewIPv4AddressFromVals(WrapSegmentValueProviderForIPv4(lowerValueProvider)).ToIP()
	} else if version.IsIPv6() {
		return NewIPv6AddressFromVals(WrapSegmentValueProviderForIPv6(lowerValueProvider)).ToIP()
	}
	return nil
}

// NewIPAddressFromPrefixedVals constructs an IPAddress from the provided segment values and prefix length.
// If the given version is indeterminate, then nil is returned.
// The prefix length is adjusted to 0 if negative or to the bit count if larger.
func NewIPAddressFromPrefixedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return NewIPAddressFromPrefixedZonedVals(version, lowerValueProvider, upperValueProvider, prefixLength, "")
}

// NewIPAddressFromPrefixedZonedVals constructs an IPAddress from the provided segment values, prefix length, and zone.
// If the given version is indeterminate, then nil is returned.
// If the version is IPv4, then the zone is ignored.
// The prefix length is adjusted to 0 if negative or to the bit count if larger.
func NewIPAddressFromPrefixedZonedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	if version.IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(
			WrapSegmentValueProviderForIPv4(lowerValueProvider),
			WrapSegmentValueProviderForIPv4(upperValueProvider),
			prefixLength).ToIP()
	} else if version.IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(
			WrapSegmentValueProviderForIPv6(lowerValueProvider),
			WrapSegmentValueProviderForIPv6(upperValueProvider),
			prefixLength,
			zone).ToIP()
	}
	return nil
}

// NewIPAddressFromValueProvider constructs an IPAddress from the provided segment values, prefix length, and zone,
// all of which are supplied by the implementation of IPAddressValueProvider.
// If the given version is indeterminate, then nil is returned.
// If the version is IPv4, then the zone is ignored.
// The prefix length is adjusted to 0 if negative or to the bit count if larger.
func NewIPAddressFromValueProvider(valueProvider IPAddressValueProvider) *IPAddress {
	if valueProvider.GetIPVersion().IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(
			WrapSegmentValueProviderForIPv4(valueProvider.GetValues()),
			WrapSegmentValueProviderForIPv4(valueProvider.GetUpperValues()),
			valueProvider.GetPrefixLen()).ToIP()
	} else if valueProvider.GetIPVersion().IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(
			WrapSegmentValueProviderForIPv6(valueProvider.GetValues()),
			WrapSegmentValueProviderForIPv6(valueProvider.GetUpperValues()),
			valueProvider.GetPrefixLen(),
			valueProvider.GetZone()).ToIP()
	}
	return nil
}

func allVersionsMatch(one *IPAddress, two []*IPAddress) bool {
	addrType := one.getAddrType()
	for _, addr := range two {
		if addr.getAddrType() != addrType {
			return false
		}
	}
	return true
}
