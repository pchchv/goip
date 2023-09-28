package goip

import (
	"math/big"
	"net"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

const (
	NoZone                           = ""
	IPv6SegmentSeparator             = ':'
	IPv6SegmentSeparatorStr          = ":"
	IPv6ZoneSeparator                = '%'
	IPv6ZoneSeparatorStr             = "%"
	IPv6AlternativeZoneSeparator     = '\u00a7'
	IPv6AlternativeZoneSeparatorStr  = "\u00a7" //'§'
	IPv6BitsPerSegment               = 16
	IPv6BytesPerSegment              = 2
	IPv6SegmentCount                 = 8
	IPv6MixedReplacedSegmentCount    = 2
	IPv6MixedOriginalSegmentCount    = 6
	IPv6MixedOriginalByteCount       = 12
	IPv6ByteCount                    = 16
	IPv6BitCount                     = 128
	IPv6DefaultTextualRadix          = 16
	IPv6MaxValuePerSegment           = 0xffff
	IPv6ReverseDnsSuffix             = ".ip6.arpa"
	IPv6ReverseDnsSuffixDeprecated   = ".ip6.int"
	IPv6UncSegmentSeparator          = '-'
	IPv6UncSegmentSeparatorStr       = "-"
	IPv6UncZoneSeparator             = 's'
	IPv6UncZoneSeparatorStr          = "s"
	IPv6UncRangeSeparator            = AlternativeRangeSeparator
	IPv6UncRangeSeparatorStr         = AlternativeRangeSeparatorStr
	IPv6UncSuffix                    = ".ipv6-literal.net"
	IPv6SegmentMaxChars              = 4
	ipv6BitsToSegmentBitshift        = 4
	IPv6AlternativeRangeSeparatorStr = AlternativeRangeSeparatorStr
)

var (
	zeroIPv6 = initZeroIPv6()
	ipv6All  = zeroIPv6.ToPrefixBlockLen(0)
)

// Zone represents an IPv6 address zone or scope.
type Zone string

// IsEmpty returns whether the zone is the zero-zone,
// which is the lack of a zone, or the empty string zone.
func (zone Zone) IsEmpty() bool {
	return zone == ""
}

// String implements the [fmt.Stringer] interface,
// returning the zone characters as a string
func (zone Zone) String() string {
	return string(zone)
}

// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.
// An IPv6 address is composed of 8 2-byte segments and can optionally have an associated prefix length.
// Each segment can represent a single value or a range of values.
// The zero value is "::".
//
// To construct one from a string, use NewIPAddressString, then use the ToAddress or GetAddress method of [IPAddressString],
// and then use ToIPv6 to get an IPv6Address, assuming the string had an IPv6 format.
//
// For other inputs, use one of the multiple constructor functions like NewIPv6Address.
// You can also use one of the multiple constructors for [IPAddress] like NewIPAddress and then convert using ToIPv6.
type IPv6Address struct {
	ipAddressInternal
}

func (addr *IPv6Address) init() *IPv6Address {
	if addr.section == nil {
		return zeroIPv6
	}
	return addr
}

// ToPrefixBlock returns the subnet associated with the prefix length of this address.
// If this address has no prefix length, this address is returned.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block".
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1:2:3:4:5:6:7:8/64" it returns the subnet "1:2:3:4::/64" which can also be written as "1:2:3:4:*:*:*:*/64".
func (addr *IPv6Address) ToPrefixBlock() *IPv6Address {
	return addr.init().toPrefixBlock().ToIPv6()
}

// ToPrefixBlockLen returns the subnet associated with the given prefix length.
//
// The subnet will include all addresses with the same prefix as this one, the prefix "block" for that prefix length.
// The network prefix will match the prefix of this address or subnet, and the host values will span all values.
//
// For example, if the address is "1:2:3:4:5:6:7:8" and the prefix length provided is 64, it returns the subnet "1:2:3:4::/64" which can also be written as "1:2:3:4:*:*:*:*/64".
func (addr *IPv6Address) ToPrefixBlockLen(prefLen BitCount) *IPv6Address {
	return addr.init().toPrefixBlockLen(prefLen).ToIPv6()
}

// ToIP converts to an IPAddress, a polymorphic type usable with all IP addresses and subnets.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv6Address) ToIP() *IPAddress {
	if addr != nil {
		addr = addr.init()
	}
	return (*IPAddress)(addr)
}

// ToAddressBase converts to an Address, a polymorphic type usable with all addresses and subnets.
// Afterwards, you can convert back with ToIPv6.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *IPv6Address) ToAddressBase() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

// GetCount returns the count of addresses that this address or subnet represents.
//
// If just a single address, not a subnet of multiple addresses, returns 1.
//
// For instance, the IP address subnet "2001:db8::/64" has the count of 2 to the power of 64.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *IPv6Address) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address,
// whether it is a subnet of multiple addresses.
func (addr *IPv6Address) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *IPv6Address) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// IsFullRange returns whether this address covers the entire IPv6 address space.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (addr *IPv6Address) IsFullRange() bool {
	return addr.GetSection().IsFullRange()
}

// GetSection returns the backing section for this address or subnet, comprising all segments.
func (addr *IPv6Address) GetSection() *IPv6AddressSection {
	return addr.init().section.ToIPv6()
}

// GetBitCount returns the number of bits comprising this address,
// or each address in the range if a subnet, which is 128.
func (addr *IPv6Address) GetBitCount() BitCount {
	return IPv6BitCount
}

// GetByteCount returns the number of bytes required for this address,
// or each address in the range if a subnet, which is 16.
func (addr *IPv6Address) GetByteCount() int {
	return IPv6ByteCount
}

// GetBitsPerSegment returns the number of bits comprising each segment in this address.
// Segments in the same address are equal length.
func (addr *IPv6Address) GetBitsPerSegment() BitCount {
	return IPv6BitsPerSegment
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this address or subnet.
// Segments in the same address are equal length.
func (addr *IPv6Address) GetBytesPerSegment() int {
	return IPv6BytesPerSegment
}

// HasZone returns whether this IPv6 address includes a zone or scope.
func (addr *IPv6Address) HasZone() bool {
	return addr != nil && addr.zone != NoZone
}

// GetZone returns the zone it it has one, otherwise it returns NoZone, which is an empty string.
func (addr *IPv6Address) GetZone() Zone {
	if addr == nil {
		return NoZone
	}
	return addr.zone
}

// GetNetworkMask returns the network mask associated with the CIDR network prefix length of this address or subnet.
// If this address or subnet has no prefix length, then the all-ones mask is returned.
func (addr *IPv6Address) GetNetworkMask() *IPv6Address {
	var prefLen BitCount
	if pref := addr.getPrefixLen(); pref != nil {
		prefLen = pref.bitCount()
	} else {
		prefLen = IPv6BitCount
	}
	return ipv6Network.GetNetworkMask(prefLen).ToIPv6()
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (addr *IPv6Address) CopySegments(segs []*IPv6AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.
// The returned slice is not backed by the same array as this address.
func (addr *IPv6Address) GetSegments() []*IPv6AddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (addr *IPv6Address) GetSegment(index int) *IPv6AddressSegment {
	return addr.init().getSegment(index).ToIPv6()
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0, calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (addr *IPv6Address) ForEachSegment(consumer func(segmentIndex int, segment *IPv6AddressSegment) (stop bool)) int {
	return addr.GetSection().ForEachSegment(consumer)
}

// GetDivisionCount returns the segment count.
func (addr *IPv6Address) GetDivisionCount() int {
	return addr.init().getDivisionCount()
}

// GetIPVersion returns IPv6, the IP version of this address.
func (addr *IPv6Address) GetIPVersion() IPVersion {
	return IPv6
}

func (addr *IPv6Address) checkIdentity(section *IPv6AddressSection) *IPv6Address {
	if section == nil {
		return nil
	}

	sec := section.ToSectionBase()
	if sec == addr.section {
		return addr
	}

	return newIPv6AddressZoned(section, string(addr.zone))
}

// GetLower returns the lowest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for "1::1:2-3:4:5-6", the series "1::1:2:4:5" is returned.
func (addr *IPv6Address) GetLower() *IPv6Address {
	return addr.init().getLower().ToIPv6()
}

// GetUpper returns the highest address in the subnet range,
// which will be the receiver if it represents a single address.
// For example, for "1::1:2-3:4:5-6", the series "1::1:3:4:6" is returned.
func (addr *IPv6Address) GetUpper() *IPv6Address {
	return addr.init().getUpper().ToIPv6()
}

// GetLowerIPAddress returns the address in the subnet or address collection with the lowest numeric value,
// which will be the receiver if it represents a single address.
// GetLowerIPAddress implements the IPAddressRange interface
func (addr *IPv6Address) GetLowerIPAddress() *IPAddress {
	return addr.GetLower().ToIP()
}

// GetUpperIPAddress returns the address in the subnet or address collection with the highest numeric value,
// which will be the receiver if it represents a single address.
// GetUpperIPAddress implements the IPAddressRange interface
func (addr *IPv6Address) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper().ToIP()
}

// ToBlock creates a new block of addresses by changing
// the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr *IPv6Address) ToBlock(segmentIndex int, lower, upper SegInt) *IPv6Address {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPv6()
}

// SetPrefixLen sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the address.
// The provided prefix length will be adjusted to these boundaries if necessary.
func (addr *IPv6Address) SetPrefixLen(prefixLen BitCount) *IPv6Address {
	return addr.init().setPrefixLen(prefixLen).ToIPv6()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the address.
//
// If this address has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr *IPv6Address) AdjustPrefixLen(prefixLen BitCount) *IPv6Address {
	return addr.init().adjustPrefixLen(prefixLen).ToIPv6()
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
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr *IPv6Address) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv6Address, address_error.IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

// GetValue returns the lowest address in this subnet or address as an integer value.
func (addr *IPv6Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

// GetUpperValue returns the highest address in this subnet or address as an integer value.
func (addr *IPv6Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

// GetNetIPAddr returns the lowest address in this subnet or address as a net.IPAddr.
func (addr *IPv6Address) GetNetIPAddr() *net.IPAddr {
	return addr.ToIP().GetNetIPAddr()
}

// GetUpperNetIPAddr returns the highest address in this subnet or address as a net.IPAddr.
func (addr *IPv6Address) GetUpperNetIPAddr() *net.IPAddr {
	return addr.ToIP().GetUpperNetIPAddr()
}

// Bytes returns the lowest address in this subnet or address as a byte slice.
func (addr *IPv6Address) Bytes() []byte {
	return addr.init().section.Bytes()
}

// UpperBytes returns the highest address in this subnet or address as a byte slice.
func (addr *IPv6Address) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

// CopyBytes copies the value of the lowest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv6Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

// CopyUpperBytes copies the value of the highest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *IPv6Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

// IsMax returns whether this address matches exactly the maximum possible value, the address whose bits are all ones.
func (addr *IPv6Address) IsMax() bool {
	return addr.init().section.IsMax()
}

// IncludesMax returns whether this address includes the max address, the address whose bits are all ones, within its range.
func (addr *IPv6Address) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// GetMaxSegmentValue returns the maximum possible segment value for this type of address.
//
// Note this is not the maximum of the range of segment values in this specific address,
// this is the maximum value of any segment for this address type and version, determined by the number of bits per segment.
func (addr *IPv6Address) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

// WithoutZone returns the same address but with no zone.
func (addr *IPv6Address) WithoutZone() *IPv6Address {
	if addr.HasZone() {
		return newIPv6Address(addr.GetSection())
	}
	return addr
}

// SetZone returns the same address associated with the given zone.
// The existing zone, if any, is replaced.
func (addr *IPv6Address) SetZone(zone string) *IPv6Address {
	if Zone(zone) == addr.GetZone() {
		return addr
	}
	return newIPv6AddressZoned(addr.GetSection(), zone)
}

func (addr *IPv6Address) getLowestHighestAddrs() (lower, upper *IPv6Address) {
	l, u := addr.ipAddressInternal.getLowestHighestAddrs()
	return l.ToIPv6(), u.ToIPv6()
}

// IsUniqueLocal returns true if the address is unique-local, or all addresses in the subnet are unique-local, see RFC 4193.
func (addr *IPv6Address) IsUniqueLocal() bool {
	// RFC 4193
	return addr.GetSegment(0).MatchesWithPrefixMask(0xfc00, 7)
}

// IsIPv4Mapped returns whether the address or all addresses in the subnet are IPv4-mapped.
//
// "::ffff:x:x/96" indicates an IPv6 address mapped to IPv4.
func (addr *IPv6Address) IsIPv4Mapped() bool {
	//::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	if addr.GetSegment(5).Matches(IPv6MaxValuePerSegment) {
		for i := 0; i < 5; i++ {
			if !addr.GetSegment(i).IsZero() {
				return false
			}
		}
		return true
	}
	return false
}

// IsIPv4Compatible returns whether the address or all addresses in the subnet are IPv4-compatible.
func (addr *IPv6Address) IsIPv4Compatible() bool {
	return addr.GetSegment(0).IsZero() && addr.GetSegment(1).IsZero() && addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() && addr.GetSegment(4).IsZero() && addr.GetSegment(5).IsZero()
}

// Is6To4 returns whether the address or subnet is IPv6 to IPv4 relay.
func (addr *IPv6Address) Is6To4() bool {
	// 2002::/16
	return addr.GetSegment(0).Matches(0x2002)
}

// Is6Over4 returns whether the address or all addresses in the subnet are 6over4.
func (addr *IPv6Address) Is6Over4() bool {
	return addr.GetSegment(0).Matches(0xfe80) &&
		addr.GetSegment(1).IsZero() && addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() && addr.GetSegment(4).IsZero() &&
		addr.GetSegment(5).IsZero()
}

// IsTeredo returns whether the address or all addresses in the subnet are Teredo.
func (addr *IPv6Address) IsTeredo() bool {
	// 2001::/32
	return addr.GetSegment(0).Matches(0x2001) && addr.GetSegment(1).IsZero()
}

// IsIsatap returns whether the address or all addresses in the subnet are ISATAP.
func (addr *IPv6Address) IsIsatap() bool {
	// 0,1,2,3 is fe80::
	// 4 can be 0200
	return addr.GetSegment(0).Matches(0xfe80) &&
		addr.GetSegment(1).IsZero() &&
		addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero() &&
		(addr.GetSegment(4).IsZero() || addr.GetSegment(4).Matches(0x200)) &&
		addr.GetSegment(5).Matches(0x5efe)
}

// IsIPv4Translatable returns whether the address or subnet is IPv4 translatable as in RFC 2765.
func (addr *IPv6Address) IsIPv4Translatable() bool { //rfc 2765
	//::ffff:0:x:x/96 indicates IPv6 addresses translated from IPv4
	return addr.GetSegment(4).Matches(0xffff) &&
		addr.GetSegment(5).IsZero() &&
		addr.GetSegment(0).IsZero() &&
		addr.GetSegment(1).IsZero() &&
		addr.GetSegment(2).IsZero() &&
		addr.GetSegment(3).IsZero()
}

// IsWellKnownIPv4Translatable returns whether the address has the well-known prefix for IPv4-translatable addresses as in RFC 6052 and RFC 6144.
func (addr *IPv6Address) IsWellKnownIPv4Translatable() bool { //rfc 6052 rfc 6144
	//64:ff9b::/96 prefix for auto ipv4/ipv6 translation
	if addr.GetSegment(0).Matches(0x64) && addr.GetSegment(1).Matches(0xff9b) {
		for i := 2; i <= 5; i++ {
			if !addr.GetSegment(i).IsZero() {
				return false
			}
		}
		return true
	}
	return false
}

// IsMulticast returns whether this address or subnet is entirely multicast.
func (addr *IPv6Address) IsMulticast() bool {
	// 11111111...
	return addr.GetSegment(0).MatchesWithPrefixMask(0xff00, 8)
}

func newIPv6Address(section *IPv6AddressSection) *IPv6Address {
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6()
}

func initZeroIPv6() *IPv6Address {
	div := zeroIPv6Seg
	segs := []*IPv6AddressSegment{div, div, div, div, div, div, div, div}
	section := NewIPv6Section(segs)
	return newIPv6Address(section)
}

// NewIPv6Address constructs an IPv6 address or subnet from the given address section.
// If the section does not have 8 segments, an error is returned.
func NewIPv6Address(section *IPv6AddressSection) (*IPv6Address, address_error.AddressValueError) {
	if section == nil {
		return zeroIPv6, nil
	}
	segCount := section.GetSegmentCount()
	if segCount != IPv6SegmentCount {
		return nil, &addressValueError{
			addressError: addressError{key: "ipaddress.error.invalid.size"},
			val:          segCount,
		}
	}
	return createAddress(section.ToSectionBase(), NoZone).ToIPv6(), nil
}

func newIPv6AddressZoned(section *IPv6AddressSection, zone string) *IPv6Address {
	zoneVal := Zone(zone)
	result := createAddress(section.ToSectionBase(), zoneVal).ToIPv6()
	assignIPv6Cache(zoneVal, result.cache)
	return result
}

func assignIPv6Cache(zoneVal Zone, cache *addressCache) {
	if zoneVal != NoZone { // will need to cache its own strings
		cache.stringCache = &stringCache{ipv6StringCache: &ipv6StringCache{}, ipStringCache: &ipStringCache{}}
	}
}

// NewIPv6AddressFromBytes constructs an IPv6 address from the given byte slice.
// An error is returned when the byte slice has too many bytes to match the IPv6 segment count of 8.
// There should be 16 bytes or less, although extra leading zeros are tolerated.
func NewIPv6AddressFromBytes(bytes []byte) (addr *IPv6Address, err address_error.AddressValueError) {
	section, err := NewIPv6SectionFromSegmentedBytes(bytes, IPv6SegmentCount)
	if err == nil {
		addr = newIPv6Address(section)
	}
	return
}

// NewIPv6AddressFromZonedBytes constructs an IPv6 address from the given byte slice and zone.
// An error is returned when the byte slice has too many bytes to match the IPv6 segment count of 8.
// There should be 16 bytes or less, although extra leading zeros are tolerated.
func NewIPv6AddressFromZonedBytes(bytes []byte, zone string) (addr *IPv6Address, err address_error.AddressValueError) {
	addr, err = NewIPv6AddressFromBytes(bytes)
	if err == nil {
		addr.zone = Zone(zone)
		assignIPv6Cache(addr.zone, addr.cache)
	}
	return
}
