package goip

import (
	"math/big"
	"net"
	"net/netip"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

const (
	IPv4SegmentSeparator      = '.'
	IPv4SegmentSeparatorStr   = "."
	IPv4BitsPerSegment        = 8
	IPv4BytesPerSegment       = 1
	IPv4SegmentCount          = 4
	IPv4ByteCount             = 4
	IPv4BitCount              = 32
	IPv4DefaultTextualRadix   = 10
	IPv4MaxValuePerSegment    = 0xff
	IPv4MaxValue              = 0xffffffff
	IPv4ReverseDnsSuffix      = ".in-addr.arpa"
	IPv4SegmentMaxChars       = 3
	ipv4BitsToSegmentBitshift = 3
)

var (
	zeroIPv4 = initZeroIPv4()
	ipv4All  = zeroIPv4.ToPrefixBlockLen(0)
)

// IPv4Address is an IPv4 address, or a subnet of multiple IPv4 addresses.
// An IPv4 address is composed of 4 1-byte segments and can optionally have an associated prefix length.
// Each segment can represent a single value or a range of values.
// The zero value is "0.0.0.0".
//
// To construct one from a string, use NewIPAddressString, then use the ToAddress or GetAddress method of [IPAddressString],
// and then use ToIPv4 to get an IPv4Address, assuming the string had an IPv4 format.
//
// For other inputs, use one of the multiple constructor functions like NewIPv4Address.
// You can also use one of the multiple constructors for [IPAddress] like NewIPAddress and then convert using ToIPv4.
type IPv4Address struct {
	ipAddressInternal
}

func (addr *IPv4Address) init() *IPv4Address {
	if addr.section == nil {
		return zeroIPv4
	}
	return addr
}

// ToPrefixBlockLen returns the subnet associated with the given prefix length.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block" for that prefix length.
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1.2.3.4" and the prefix length provided is 16, it returns the subnet "1.2.0.0/16", which can also be written as "1.2.*.*/16".
func (addr *IPv4Address) ToPrefixBlockLen(prefLen BitCount) *IPv4Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv4()
}

// ToIP converts to an IPAddress, a polymorphic type usable with all IP addresses and subnets.
// Afterwards, you can convert back with ToIPv4.
//
// ToIP can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv4Address) ToIP() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(addr)
}

// Wrap wraps this IP address, returning a WrappedIPAddress, an implementation of ExtendedIPSegmentSeries,
// which can be used to write code that works with both IP addresses and IP address sections.
// Wrap can be called with a nil receiver, wrapping a nil address.
func (addr *IPv4Address) Wrap() WrappedIPAddress {
	return wrapIPAddress(addr.ToIP())
}

// WrapAddress wraps this IP address, returning a WrappedAddress, an implementation of ExtendedSegmentSeries,
// which can be used to write code that works with both addresses and address sections.
// WrapAddress can be called with a nil receiver, wrapping a nil address.
func (addr *IPv4Address) WrapAddress() WrappedAddress {
	return wrapAddress(addr.ToAddressBase())
}

// GetSection returns the backing section for this address or subnet, comprising all segments.
func (addr *IPv4Address) GetSection() *IPv4AddressSection {
	return addr.init().section.ToIPv4()
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToIPv4.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv4Address) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

// GetCount returns the count of addresses that this address or subnet represents.
//
// If just a single address, not a subnet of multiple addresses, returns 1.
//
// For instance, the IP address subnet "1.2.0.0/15" has the count of 2 to the power of 17.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *IPv4Address) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address, whether it is a subnet of multiple addresses.
func (addr *IPv4Address) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *IPv4Address) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// IsFullRange returns whether this address covers the entire IPv4 address space.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (addr *IPv4Address) IsFullRange() bool {
	return addr.GetSection().IsFullRange()
}

// GetBitCount returns the number of bits comprising this address,
// or each address in the range if a subnet, which is 32.
func (addr *IPv4Address) GetBitCount() BitCount {
	return IPv4BitCount
}

// GetByteCount returns the number of bytes required for this address,
// or each address in the range if a subnet, which is 4.
func (addr *IPv4Address) GetByteCount() int {
	return IPv4ByteCount
}

// GetBitsPerSegment returns the number of bits comprising each segment in this address.
// Segments in the same address are equal length.
func (addr *IPv4Address) GetBitsPerSegment() BitCount {
	return IPv4BitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this address or subnet.
// Segments in the same address are equal length.
func (addr *IPv4Address) GetBytesPerSegment() int {
	return IPv4BytesPerSegment
}

// GetNetworkMask returns the network mask associated with
// the CIDR network prefix length of this address or subnet.
// If this address or subnet has no prefix length,
// then the all-ones mask is returned.
func (addr *IPv4Address) GetNetworkMask() *IPv4Address {
	var prefLen BitCount
	if pref := addr.getPrefixLen(); pref != nil {
		prefLen = pref.bitCount()
	} else {
		prefLen = IPv4BitCount
	}
	return ipv4Network.GetNetworkMask(prefLen).ToIPv4()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or
// an index matching or larger than the segment count.
func (addr *IPv4Address) GetSegment(index int) *IPv4AddressSegment {
	return addr.init().getSegment(index).ToIPv4()
}

// GetDivisionCount returns the segment count.
func (addr *IPv4Address) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

// GetIPVersion returns IPv4, the IP version of this address.
func (addr *IPv4Address) GetIPVersion() IPVersion {
	return IPv4
}

func (addr *IPv4Address) checkIdentity(section *IPv4AddressSection) *IPv4Address {
	if section == nil {
		return nil
	}
	sec := section.ToSectionBase()
	if sec == addr.section {
		return addr
	}
	return newIPv4Address(section)
}

// GetLower returns the lowest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
func (addr *IPv4Address) GetLower() *IPv4Address {
	return addr.init().getLower().ToIPv4()
}

// GetUpper returns the highest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the address "1.3.4.6" is returned.
func (addr *IPv4Address) GetUpper() *IPv4Address {
	return addr.init().getUpper().ToIPv4()
}

// GetLowerIPAddress returns the address in the subnet or address collection with the lowest numeric value,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
// GetLowerIPAddress implements the IPAddressRange interface
func (addr *IPv4Address) GetLowerIPAddress() *IPAddress {
	return addr.GetLower().ToIP()
}

// GetUpperIPAddress returns the address in the subnet or address collection with the highest numeric value,
// which will be the receiver if it represents a single address.
// For example, for the subnet "1.2-3.4.5-6", the address "1.3.4.6" is returned.
// GetUpperIPAddress implements the IPAddressRange interface
func (addr *IPv4Address) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper().ToIP()
}

// ToPrefixBlock returns the subnet associated with the prefix length of this address.
// If this address has no prefix length, this address is returned.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block".
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1.2.3.4/16" it returns the subnet "1.2.0.0/16", which can also be written as "1.2.*.* /16".
func (addr *IPv4Address) ToPrefixBlock() *IPv4Address {
	return addr.init().toPrefixBlock().ToIPv4()
}

// ToBlock creates a new block of addresses by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr *IPv4Address) ToBlock(segmentIndex int, lower, upper SegInt) *IPv4Address {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPv4()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (addr *IPv4Address) SetPrefixLen(prefixLen BitCount) *IPv4Address {
	return addr.init().setPrefixLen(prefixLen).ToIPv4()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr *IPv4Address) AdjustPrefixLen(prefixLen BitCount) *IPv4Address {
	return addr.init().adjustPrefixLen(prefixLen).ToIPv4()
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by the given increment while zeroing out the bits that have moved into or outside the prefix.
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
func (addr *IPv4Address) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv4Address, address_error.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv4(), err
}

// GetValue returns the lowest address in this subnet or address as an integer value.
func (addr *IPv4Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

// GetUpperValue returns the highest address in this subnet or address as an integer value.
func (addr *IPv4Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

// Bytes returns the lowest address in this subnet or address as a byte slice.
func (addr *IPv4Address) Bytes() []byte {
	return addr.init().section.Bytes()
}

// UpperBytes returns the highest address in this subnet or address as a byte slice.
func (addr *IPv4Address) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

// CopyBytes copies the value of the lowest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv4Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

// CopyUpperBytes copies the value of the highest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv4Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

// UpperUint32Value returns the highest address in the subnet range as a uint32.
func (addr *IPv4Address) UpperUint32Value() uint32 {
	return addr.GetSection().UpperUint32Value()
}

// IsMax returns whether this address matches exactly the maximum possible value, the address whose bits are all ones.
func (addr *IPv4Address) IsMax() bool {
	return addr.init().section.IsMax()
}

// IncludesMax returns whether this address includes the max address, the address whose bits are all ones, within its range.
func (addr *IPv4Address) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (addr *IPv4Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPv4Address) getLowestHighestAddrs() (lower, upper *IPv4Address) {
	l, u := addr.ipAddressInternal.getLowestHighestAddrs()
	return l.ToIPv4(), u.ToIPv4()
}

// IsPrivate returns whether this is a unicast addresses allocated for private use,
// as defined by RFC 1918.
func (addr *IPv4Address) IsPrivate() bool {
	// refer to RFC 1918
	// 10/8 prefix
	// 172.16/12 prefix (172.16.0.0 – 172.31.255.255)
	// 192.168/16 prefix
	seg0, seg1 := addr.GetSegment(0), addr.GetSegment(1)
	return seg0.Matches(10) ||
		(seg0.Matches(172) && seg1.MatchesWithPrefixMask(16, 4)) ||
		(seg0.Matches(192) && seg1.Matches(168))
}

// IsMulticast returns whether this address or subnet is entirely multicast.
func (addr *IPv4Address) IsMulticast() bool {
	// 1110...
	// 224.0.0.0/4
	return addr.GetSegment(0).MatchesWithPrefixMask(0xe0, 4)
}

// IsLoopback returns whether this address is a loopback address, such as "127.0.0.1".
func (addr *IPv4Address) IsLoopback() bool {
	return addr.section != nil && addr.GetSegment(0).Matches(127)
}

// GetNetwork returns the singleton IPv4 network instance.
func (addr *IPv4Address) GetNetwork() IPAddressNetwork {
	return ipv4Network
}

// toAddressBase is needed for tries, it skips the init() call
func (addr *IPv4Address) toAddressBase() *Address {
	return (*Address)(unsafe.Pointer(addr))
}

// GetIPv4Count returns the count of possible distinct values for this section.
// It is the same as GetCount but returns the value as a uint64 instead of a big integer.
// If not representing multiple values, the count is 1.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *IPv4Address) GetIPv4Count() uint64 {
	if addr == nil {
		return 0
	}
	return addr.GetSection().GetIPv4Count()
}

// GetIPv4PrefixCount returns the number of distinct prefix values in this section.
// It is the same as GetPrefixCount but returns the value as a uint64 instead of a big integer.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the number of distinct prefix values.
//
// If this has a nil prefix length, returns the same value as GetIPv4Count.
func (addr *IPv4Address) GetIPv4PrefixCount() uint64 {
	return addr.GetSection().GetIPv4PrefixCount()
}

// GetIPv4PrefixCountLen gives count available as a uint64 instead of big.Int.
//
// It is the similar to GetPrefixCountLen but returns a uint64, not a *big.Int
func (addr *IPv4Address) GetIPv4PrefixCountLen(prefixLength BitCount) uint64 {
	return addr.GetSection().GetIPv4PrefixCountLen(prefixLength)
}

// GetIPv4BlockCount returns the count of distinct values in
// the given number of initial (more significant) segments.
//
// It is similar to GetBlockCount but returns a uint64 instead of a big integer.
func (addr *IPv4Address) GetIPv4BlockCount(segmentCount int) uint64 {
	return addr.GetSection().GetIPv4BlockCount(segmentCount)
}

// GetNetworkSection returns an address section containing the segments with the network of the address or subnet, the prefix bits.
// The returned section will have only as many segments as needed as determined by the existing CIDR network prefix length.
//
// If this series has no CIDR prefix length, the returned network section will
// be the entire series as a prefixed section with prefix length matching the address bit length.
func (addr *IPv4Address) GetNetworkSection() *IPv4AddressSection {
	return addr.GetSection().GetNetworkSection()
}

// GetNetworkSectionLen returns a section containing the segments with the network of the address or subnet, the prefix bits according to the given prefix length.
// The returned section will have only as many segments as needed to contain the network.
//
// The new section will be assigned the given prefix length,
// unless the existing prefix length is smaller, in which case the existing prefix length will be retained.
func (addr *IPv4Address) GetNetworkSectionLen(prefLen BitCount) *IPv4AddressSection {
	return addr.GetSection().GetNetworkSectionLen(prefLen)
}

// GetHostSection returns a section containing the segments with the host of the address or subnet,
// the bits beyond the CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
//
// If this series has no prefix length, the returned host section will be the full section.
func (addr *IPv4Address) GetHostSection() *IPv4AddressSection {
	return addr.GetSection().GetHostSection()
}

// GetHostSectionLen returns a section containing the segments with the host of the address or subnet,
// the bits beyond the given CIDR network prefix length.
// The returned section will have only as many segments as needed to contain the host.
func (addr *IPv4Address) GetHostSectionLen(prefLen BitCount) *IPv4AddressSection {
	return addr.GetSection().GetHostSectionLen(prefLen)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (addr *IPv4Address) CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (addr *IPv4Address) CopySegments(segs []*IPv4AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this address.
func (addr *IPv4Address) GetSegments() []*IPv4AddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegmentCount returns the segment count, the number of segments in this address, which is 4.
func (addr *IPv4Address) GetSegmentCount() int {
	return addr.GetDivisionCount()
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0,
// calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (addr *IPv4Address) ForEachSegment(consumer func(segmentIndex int, segment *IPv4AddressSegment) (stop bool)) int {
	return addr.GetSection().ForEachSegment(consumer)
}

// GetHostMask returns the host mask associated with the CIDR network prefix length of this address or subnet.
// If this address or subnet has no prefix length, then the all-ones mask is returned.
func (addr *IPv4Address) GetHostMask() *IPv4Address {
	return addr.getHostMask(ipv4Network).ToIPv4()
}

// Mask applies the given mask to all addresses represented by this IPv4Address.
// The mask is applied to all individual addresses.
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a sequential range within each segment, then an error is returned.
func (addr *IPv4Address) Mask(other *IPv4Address) (masked *IPv4Address, err address_error.IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

func (addr *IPv4Address) maskPrefixed(other *IPv4Address, retainPrefix bool) (masked *IPv4Address, err address_error.IncompatibleAddressError) {
	addr = addr.init()
	sect, err := addr.GetSection().maskPrefixed(other.GetSection(), retainPrefix)
	if err == nil {
		masked = addr.checkIdentity(sect)
	}
	return
}

// IsZeroHostLen returns whether the host section is always zero for all individual addresses in this subnet,
// for the given prefix length.
//
// If the host section is zero length (there are zero host bits), IsZeroHostLen returns true.
func (addr *IPv4Address) IsZeroHostLen(prefLen BitCount) bool {
	return addr.init().isZeroHostLen(prefLen)
}

// IsMaxHostLen returns whether the host is all one-bits, the max value, for all individual addresses in this subnet,
// for the given prefix length, the host being the bits following the prefix.
//
// If the host section is zero length (there are zero host bits), IsMaxHostLen returns true.
func (addr *IPv4Address) IsMaxHostLen(prefLen BitCount) bool {
	return addr.init().isMaxHostLen(prefLen)
}

// WithoutPrefixLen provides the same address but with no prefix length.
// The values remain unchanged.
func (addr *IPv4Address) WithoutPrefixLen() *IPv4Address {
	if !addr.IsPrefixed() {
		return addr
	}
	return addr.init().withoutPrefixLen().ToIPv4()
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
func (addr *IPv4Address) SetPrefixLenZeroed(prefixLen BitCount) (*IPv4Address, address_error.IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIPv4(), err
}

// AssignMinPrefixForBlock returns an equivalent subnet,
// assigned the smallest prefix length possible,
// such that the prefix block for that prefix length is in this subnet.
//
// In other words, this method assigns a prefix length to
// this subnet matching the largest prefix block in this subnet.
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
func (addr *IPv4Address) AssignMinPrefixForBlock() *IPv4Address {
	return addr.init().assignMinPrefixForBlock().ToIPv4()
}

// ContainsPrefixBlock returns whether the range of this address or subnet contains the block of addresses for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (addr *IPv4Address) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.init().ipAddressInternal.ContainsPrefixBlock(prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this includes the block of addresses for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this represents just a single address, returns the bit length of this address.
func (addr *IPv4Address) GetMinPrefixLenForBlock() BitCount {
	return addr.init().ipAddressInternal.GetMinPrefixLenForBlock()
}

// Uint32Value returns the lowest address in the subnet range as a uint32.
func (addr *IPv4Address) Uint32Value() uint32 {
	return addr.GetSection().Uint32Value()
}

// GetNetIP returns the lowest address in this subnet or address as a net.IP.
func (addr *IPv4Address) GetNetIP() net.IP {
	return addr.Bytes()
}

// GetUpperNetIP returns the highest address in this subnet or address as a net.IP.
func (addr *IPv4Address) GetUpperNetIP() net.IP {
	return addr.UpperBytes()
}

// GetNetNetIPAddr returns the lowest address in this subnet or address range as a netip.Addr.
func (addr *IPv4Address) GetNetNetIPAddr() netip.Addr {
	return addr.init().getNetNetIPAddr()
}

// GetUpperNetNetIPAddr returns the highest address in this subnet or address range as a netip.Addr.
func (addr *IPv4Address) GetUpperNetNetIPAddr() netip.Addr {
	return addr.init().getUpperNetNetIPAddr()
}

// CopyNetIP copies the value of the lowest individual address in the subnet into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv4Address) CopyNetIP(ip net.IP) net.IP {
	if ipv4 := ip.To4(); ipv4 != nil { // this shrinks the arg to 4 bytes if it was 16
		ip = ipv4
	}
	return addr.CopyBytes(ip)
}

// CopyUpperNetIP copies the value of the highest individual address in the subnet into a net.IP.
//
// If the value can fit in the given net.IP slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv4Address) CopyUpperNetIP(ip net.IP) net.IP {
	if ipv4 := ip.To4(); ipv4 != nil { // this shrinks the arg to 4 bytes if it was 16
		ip = ipv4
	}
	return addr.CopyUpperBytes(ip)
}

// TestBit returns true if the bit in the lower value of this address at the given index is 1,
// where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this address.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (addr *IPv4Address) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// IsOneBit returns true if the bit in the lower value of this address at the given index is 1,
// where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (addr *IPv4Address) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

// Contains returns whether this is the same type and version as
// the given address or subnet and whether it contains all addresses in the given address or subnet.
func (addr *IPv4Address) Contains(other AddressType) bool {
	if other == nil || other.ToAddressBase() == nil {
		return true
	} else if addr == nil {
		return false
	}

	addr = addr.init()
	otherAddr := other.ToAddressBase()
	if addr.ToAddressBase() == otherAddr {
		return true
	}

	return otherAddr.getAddrType() == ipv4Type && addr.section.sameCountTypeContains(otherAddr.GetSection())
}

// Equal returns whether the given address or subnet is equal to this address or subnet.
// Two address instances are equal if they represent the same set of addresses.
func (addr *IPv4Address) Equal(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddressBase() == nil
	} else if other.ToAddressBase() == nil {
		return false
	}
	return other.ToAddressBase().getAddrType() == ipv4Type && addr.init().section.sameCountTypeEquals(other.ToAddressBase().GetSection())
}

// MatchesWithMask applies the mask to this address and then compares the result with the given address,
// returning true if they match, false otherwise.
func (addr *IPv4Address) MatchesWithMask(other *IPv4Address, mask *IPv4Address) bool {
	return addr.init().GetSection().MatchesWithMask(other.GetSection(), mask.GetSection())
}

// IncludesZeroHostLen returns whether the subnet contains an individual address with a host of zero,
// an individual address for which all bits past the given prefix length are zero.
func (addr *IPv4Address) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

// IncludesMaxHostLen returns whether the subnet contains an individual address with a host of all one-bits,
// an individual address for which all bits past the given prefix length are all ones.
func (addr *IPv4Address) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

// IsLinkLocal returns whether the address is link local, whether unicast or multicast.
func (addr *IPv4Address) IsLinkLocal() bool {
	if addr.IsMulticast() {
		// 224.0.0.252	Link-local Multicast Name Resolution	[RFC4795]
		return addr.GetSegment(0).Matches(224) && addr.GetSegment(1).IsZero() && addr.GetSegment(2).IsZero() && addr.GetSegment(3).Matches(252)
	}
	return addr.GetSegment(0).Matches(169) && addr.GetSegment(1).Matches(254)
}

func newIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4()
}

func initZeroIPv4() *IPv4Address {
	div := zeroIPv4Seg
	segs := []*IPv4AddressSegment{div, div, div, div}
	section := NewIPv4Section(segs)
	return newIPv4Address(section)
}

// NewIPv4AddressFromBytes constructs an IPv4 address from the given byte slice.
// An error is returned when the byte slice has too many bytes to match the IPv4 segment count of 4.
// There should be 4 bytes or less, although extra leading zeros are tolerated.
func NewIPv4AddressFromBytes(bytes []byte) (addr *IPv4Address, err address_error.AddressValueError) {
	if ipv4 := net.IP(bytes).To4(); ipv4 != nil {
		bytes = ipv4
	}
	section, err := NewIPv4SectionFromSegmentedBytes(bytes, IPv4SegmentCount)
	if err == nil {
		addr = newIPv4Address(section)
	}
	return
}

// NewIPv4Address constructs an IPv4 address or subnet from the given address section.
// If the section does not have 4 segments, an error is returned.
func NewIPv4Address(section *IPv4AddressSection) (*IPv4Address, address_error.AddressValueError) {
	if section == nil {
		return zeroIPv4, nil
	}
	segCount := section.GetSegmentCount()
	if segCount != IPv4SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4(), nil
}

// NewIPv4AddressFromSegs constructs an IPv4 address or subnet from the given segments.
// If the given slice does not have 4 segments, an error is returned.
func NewIPv4AddressFromSegs(segments []*IPv4AddressSegment) (*IPv4Address, address_error.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv4SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv4Section(segments)
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4(), nil
}

// NewIPv4AddressFromPrefixedSegs constructs an IPv4 address or subnet from the given segments and prefix length.
// If the given slice does not have 4 segments, an error is returned.
// If the address has a zero host for its prefix length, the returned address will be the prefix block.
func NewIPv4AddressFromPrefixedSegs(segments []*IPv4AddressSegment, prefixLength PrefixLen) (*IPv4Address, address_error.AddressValueError) {
	segCount := len(segments)
	if segCount != IPv4SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	section := NewIPv4PrefixedSection(segments, prefixLength)
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4(), nil
}

// NewIPv4AddressFromPrefixedBytes constructs an IPv4 address or prefix block from the given byte slice and prefix length.
// An error is returned when the byte slice has too many bytes to match the IPv4 segment count of 4.
// There should be 4 bytes or less, although extra leading zeros are tolerated.
// If the address has a zero host for the given prefix length, the returned address will be the prefix block.
func NewIPv4AddressFromPrefixedBytes(bytes []byte, prefixLength PrefixLen) (addr *IPv4Address, err address_error.AddressValueError) {
	if ipv4 := net.IP(bytes).To4(); ipv4 != nil {
		bytes = ipv4
	}

	section, err := NewIPv4SectionFromPrefixedBytes(bytes, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = newIPv4Address(section)
	}

	return
}

// NewIPv4AddressFromUint32 constructs an IPv4 address from the given value.
func NewIPv4AddressFromUint32(val uint32) *IPv4Address {
	section := NewIPv4SectionFromUint32(val, IPv4SegmentCount)
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4()
}

// NewIPv4AddressFromPrefixedUint32 constructs an IPv4 address or prefix block from the given value and prefix length.
// If the address has a zero host for the given prefix length, the returned address will be the prefix block.
func NewIPv4AddressFromPrefixedUint32(val uint32, prefixLength PrefixLen) *IPv4Address {
	section := NewIPv4SectionFromPrefixedUint32(val, IPv4SegmentCount, prefixLength)
	return createAddress(section.ToSectionBase(), NoZone).ToIPv4()
}

// NewIPv4AddressFromVals constructs an IPv4 address from the given values.
func NewIPv4AddressFromVals(vals IPv4SegmentValueProvider) *IPv4Address {
	section := NewIPv4SectionFromVals(vals, IPv4SegmentCount)
	return newIPv4Address(section)
}

// NewIPv4AddressFromPrefixedVals constructs an IPv4 address or prefix block from the given values and prefix length.
// If the address has a zero host for the given prefix length, the returned address will be the prefix block.
func NewIPv4AddressFromPrefixedVals(vals IPv4SegmentValueProvider, prefixLength PrefixLen) *IPv4Address {
	section := NewIPv4SectionFromPrefixedVals(vals, IPv4SegmentCount, prefixLength)
	return newIPv4Address(section)
}

// NewIPv4AddressFromRange constructs an IPv4 subnet from the given values.
func NewIPv4AddressFromRange(vals, upperVals IPv4SegmentValueProvider) *IPv4Address {
	section := NewIPv4SectionFromRange(vals, upperVals, IPv4SegmentCount)
	return newIPv4Address(section)
}

// NewIPv4AddressFromPrefixedRange constructs an IPv4 subnet from the given values and prefix length.
// If the address has a zero host for the given prefix length, the returned address will be the prefix block.
func NewIPv4AddressFromPrefixedRange(vals, upperVals IPv4SegmentValueProvider, prefixLength PrefixLen) *IPv4Address {
	section := NewIPv4SectionFromPrefixedRange(vals, upperVals, IPv4SegmentCount, prefixLength)
	return newIPv4Address(section)
}

func newIPv4AddressFromPrefixedSingle(vals, upperVals IPv4SegmentValueProvider, prefixLength PrefixLen) *IPv4Address {
	section := newIPv4SectionFromPrefixedSingle(vals, upperVals, IPv4SegmentCount, prefixLength, true)
	return newIPv4Address(section)
}
