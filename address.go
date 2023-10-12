package goip

import (
	"math/big"
	"unsafe"

	"github.com/pchchv/goip/address_error"
)

const (
	HexPrefix                       = "0x"
	OctalPrefix                     = "0"
	BinaryPrefix                    = "0b"
	RangeSeparator                  = '-'
	RangeSeparatorStr               = "-"
	AlternativeRangeSeparator       = '\u00bb'
	AlternativeRangeSeparatorStr    = "\u00bb" // '»'
	ExtendedDigitsRangeSeparatorStr = AlternativeRangeSeparatorStr
	SegmentWildcard                 = '*'
	SegmentWildcardStr              = "*"
	SegmentSqlWildcard              = '%'
	SegmentSqlWildcardStr           = "%"
	SegmentSqlSingleWildcard        = '_'
	SegmentSqlSingleWildcardStr     = "_"
)

var (
	segmentWildcardStr = SegmentWildcardStr
	zeroAddr           = createAddress(zeroSection, NoZone)
)

func createAddress(section *AddressSection, zone Zone) *Address {
	res := &Address{
		addressInternal{
			section: section,
			zone:    zone,
			cache:   &addressCache{},
		},
	}
	return res
}

// SegmentValueProvider provides values for segments.
// Values that fall outside the segment value type range will be truncated using standard golang integer type conversions.
type SegmentValueProvider func(segmentIndex int) SegInt

// AddressValueProvider provides values for addresses.
type AddressValueProvider interface {
	GetSegmentCount() int
	GetValues() SegmentValueProvider
	GetUpperValues() SegmentValueProvider
}

// identifierStr is a string representation of an address or host name.
type identifierStr struct {
	idStr HostIdentifierString // MACAddressString or IPAddressString or HostName
}

type addrsCache struct {
	lower *Address
	upper *Address
}

type addressCache struct {
	addrsCache    *addrsCache
	stringCache   *stringCache // only used by IPv6 when there is a zone
	identifierStr *identifierStr
}

type addressInternal struct {
	section *AddressSection
	zone    Zone
	cache   *addressCache
}

// GetBitCount returns the number of bits that make up a given address,
// or each address in the range if a subnet.
func (addr *addressInternal) GetBitCount() BitCount {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetBitCount()
}

// GetByteCount returns the number of bytes required for a given address,
// or each address in the range if a subnet.
func (addr *addressInternal) GetByteCount() int {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetByteCount()
}

// GetPrefixCount returns the number of prefixes in a given address or subnet.
// The prefix length is given by GetPrefixLen.
// If the prefix length is not nil, a count of the range of values in the prefix is returned.
// If the prefix length is nil, the same value is returned as in GetCount.
func (addr *addressInternal) GetPrefixCount() *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetPrefixCount()
}

// GetPrefixCountLen returns the number of prefixes in the given address or subnet for the given prefix length.
// If it is not a subnet with multiple addresses or a subnet with a single prefix of the given prefix length, 1 is returned.
func (addr *addressInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetPrefixCountLen(prefixLen)
}

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
func (addr *addressInternal) GetBlockCount(segments int) *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetBlockCount(segments)
}

// GetPrefixLen returns the prefix length or nil if there is no prefix.
//
// A prefix length indicates the number of bits in the initial part (high significant bits) of the address that make up the prefix.
//
// A prefix is a part of the address that is not specific to that address but common amongst a group of addresses, such as a CIDR prefix block subnet.
//
// For IP addresses, the prefix is explicitly specified when the address is created.
// For example, "1.2.0.0.0/16" has a prefix length of 16, and "1.2.*.*" has no prefix length,
// although both represent the same set of addresses and are considered the same.
// Prefixes may be considered variable for a given IP address and may depend on routing.
//
// The GetMinPrefixLenForBlock and GetPrefixLenForSingleBlock methods help you obtain or determine the length of a prefix if one does not already exist.
// The ToPrefixBlockLen method allows you to create a subnet consisting of a block of addresses for any given prefix length.
//
// For MAC addresses, the prefix is initially derived from a range, so "1:2:3:*:*:*" has a prefix length of 24.
// MAC addresses derived from an address with a prefix length can retain the prefix length regardless of their own range of values.
func (addr *addressInternal) GetPrefixLen() PrefixLen {
	return addr.getPrefixLen().copy()
}

// IsSequential returns whether the given address or subnet represents a range of addresses that are sequential.
//
// In the general case for a subnet, this means that any segment that spans a range of values must be followed by segments that are full range and span all values.
//
// Individual addresses are sequential and CIDR prefix blocks are sequential.
// The "1.2.3-4.5" subnet is not sequential because the two addresses it represents, "1.2.3.5" and "1.2.4.5", are not ("1.2.3.6" is in between but not part of the subnet).
//
// Given any subnet of IP addresses, you can use the SequentialBlockIterator to convert any subnet into a set of sequential subnets.
func (addr *addressInternal) IsSequential() bool {
	section := addr.section
	if section == nil {
		return true
	}
	return section.IsSequential()
}

func (addr *addressInternal) getCount() *big.Int {
	section := addr.section
	if section == nil {
		return bigOne()
	}
	return section.GetCount()
}

func (addr *addressInternal) getPrefixLen() PrefixLen {
	if addr.section == nil {
		return nil
	}
	return addr.section.getPrefixLen()
}

// isMultiple returns true if this address represents more than single individual address, whether it is a subnet of multiple addresses.
func (addr *addressInternal) isMultiple() bool {
	return addr.section != nil && addr.section.isMultiple()
}

// isPrefixed returns whether the given address has an associated prefix length.
func (addr *addressInternal) isPrefixed() bool {
	return addr.section != nil && addr.section.IsPrefixed()
}

func (addr *addressInternal) getAddrType() addrType {
	if addr.section == nil {
		return zeroType
	}
	return addr.section.addrType
}

// isIPv4 returns whether this matches an IPv4 address.
// we allow nil receivers to allow this to be called following a failed conversion like ToIP()
func (addr *addressInternal) isIPv4() bool {
	return addr.section != nil && addr.section.matchesIPv4AddressType()
}

// isIPv6 returns whether this matches an IPv6 address.
// we allow nil receivers to allow this to be called following a failed conversion like ToIP()
func (addr *addressInternal) isIPv6() bool {
	return addr.section != nil && addr.section.matchesIPv6AddressType()
}

// isMAC returns whether this matches an MAC address.
func (addr *addressInternal) isMAC() bool {
	return addr.section != nil && addr.section.matchesMACAddressType()
}

func (addr *addressInternal) toAddress() *Address {
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *addressInternal) checkIdentity(section *AddressSection) *Address {
	if section == nil {
		return nil
	} else if section == addr.section {
		return addr.toAddress()
	}
	return createAddress(section, addr.zone)
}

func (addr *addressInternal) toPrefixBlock() *Address {
	return addr.checkIdentity(addr.section.toPrefixBlock())
}

func (addr *addressInternal) toPrefixBlockLen(prefLen BitCount) *Address {
	return addr.checkIdentity(addr.section.toPrefixBlockLen(prefLen))
}

func (addr *addressInternal) getDivision(index int) *AddressDivision {
	return addr.section.getDivision(index)
}

func (addr *addressInternal) getDivisionCount() int {
	if addr.section == nil {
		return 0
	}
	return addr.section.GetDivisionCount()
}

func (addr *addressInternal) getSegment(index int) *AddressSegment {
	return addr.section.GetSegment(index)
}

// GetBitsPerSegment returns the number of bits comprising each segment in this address or subnet.
// Segments in the same address are equal length.
func (addr *addressInternal) GetBitsPerSegment() BitCount {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetBitsPerSegment()
}

func (addr *addressInternal) createLowestHighestAddrs() (lower, upper *Address) {
	lower = addr.checkIdentity(addr.section.GetLower())
	upper = addr.checkIdentity(addr.section.GetUpper())
	return
}

func (addr *addressInternal) getLowestHighestAddrs() (lower, upper *Address) {
	if !addr.isMultiple() {
		lower = addr.toAddress()
		upper = lower
		return
	}

	cache := addr.cache
	if cache == nil {
		return addr.createLowestHighestAddrs()
	}

	cached := (*addrsCache)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache.addrsCache))))
	if cached == nil {
		cached = &addrsCache{}
		cached.lower, cached.upper = addr.createLowestHighestAddrs()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.addrsCache))
		atomicStorePointer(dataLoc, unsafe.Pointer(cached))
	}

	lower, upper = cached.lower, cached.upper
	return
}

func (addr *addressInternal) getLower() *Address {
	lower, _ := addr.getLowestHighestAddrs()
	return lower
}

func (addr *addressInternal) getUpper() *Address {
	_, upper := addr.getLowestHighestAddrs()
	return upper
}

func (addr *addressInternal) toBlock(segmentIndex int, lower, upper SegInt) *Address {
	return addr.checkIdentity(addr.section.toBlock(segmentIndex, lower, upper))
}

func (addr *addressInternal) adjustPrefixLen(prefixLen BitCount) *Address {
	return addr.checkIdentity(addr.section.adjustPrefixLen(prefixLen))
}

func (addr *addressInternal) adjustPrefixLenZeroed(prefixLen BitCount) (res *Address, err address_error.IncompatibleAddressError) {
	section, err := addr.section.adjustPrefixLenZeroed(prefixLen)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

// isIP returns whether this matches an IP address.
// It must be IPv4, IPv6, or the zero IPAddress which has no segments
// we allow nil receivers to allow this to be called following a failed conversion like ToIP()
func (addr *addressInternal) isIP() bool {
	return addr.section == nil /* zero addr */ || addr.section.matchesIPAddressType()
}

func (addr *addressInternal) getBytes() []byte {
	return addr.section.getBytes()
}

func (addr *addressInternal) getUpperBytes() []byte {
	return addr.section.getUpperBytes()
}

// GetBytesPerSegment returns the number of bytes comprising each segment in this address or subnet.
// Segments in the same address are equal length.
func (addr *addressInternal) GetBytesPerSegment() int {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetBytesPerSegment()
}

func (addr *addressInternal) getMaxSegmentValue() SegInt {
	return addr.section.GetMaxSegmentValue()
}

func (addr *addressInternal) setPrefixLen(prefixLen BitCount) *Address {
	return addr.checkIdentity(addr.section.setPrefixLen(prefixLen))
}

func (addr *addressInternal) isSameZone(other *Address) bool {
	return addr.zone == other.ToAddressBase().zone
}

func (addr *addressInternal) hasZone() bool {
	return addr.zone != NoZone
}

func (addr *addressInternal) getStringCache() *stringCache {
	cache := addr.cache
	if cache == nil {
		return nil
	}
	return addr.cache.stringCache
}

func (addr *addressInternal) getTrailingBitCount(ones bool) BitCount {
	return addr.section.GetTrailingBitCount(ones)
}

func (addr *addressInternal) getLeadingBitCount(ones bool) BitCount {
	return addr.section.GetLeadingBitCount(ones)
}

// testBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this address.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (addr *addressInternal) testBit(n BitCount) bool {
	return addr.section.TestBit(n)
}

// isOneBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the most significant bit.
// isOneBit will panic if bitIndex is less than zero or larger than the bit count of this item.
func (addr *addressInternal) isOneBit(bitIndex BitCount) bool {
	return addr.section.IsOneBit(bitIndex)
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
func (addr *addressInternal) IsPrefixBlock() bool {
	prefLen := addr.getPrefixLen()
	return prefLen != nil && addr.section.ContainsPrefixBlock(prefLen.bitCount())
}

// ContainsPrefixBlock returns whether the range of this address or subnet contains the
// block of addresses for the given prefix length.
//
// Unlike ContainsSinglePrefixBlock, whether there are multiple prefix values in
// this item for the given prefix length makes no difference.
//
// Use GetMinPrefixLenForBlock to determine the smallest prefix length for which this method returns true.
func (addr *addressInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return addr.section == nil || addr.section.ContainsPrefixBlock(prefixLen)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this includes the block of addresses for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this represents just a single address, returns the bit length of this address.
func (addr *addressInternal) GetMinPrefixLenForBlock() BitCount {
	section := addr.section
	if section == nil {
		return 0
	}
	return section.GetMinPrefixLenForBlock()
}

func (addr *addressInternal) toMaxLower() *Address {
	section := addr.section
	if section == nil {
		return addr.toAddress()
	}
	return addr.checkIdentity(addr.section.toMaxLower())
}

func (addr *addressInternal) toMinUpper() *Address {
	section := addr.section
	if section == nil {
		return addr.toAddress()
	}
	return addr.checkIdentity(addr.section.toMinUpper())
}

// IsZero returns whether this address matches exactly the value of zero.
func (addr *addressInternal) IsZero() bool {
	section := addr.section
	if section == nil {
		return true
	}
	return section.IsZero()
}

// IncludesZero returns whether this address includes the zero address within its range.
func (addr *addressInternal) IncludesZero() bool {
	section := addr.section
	if section == nil {
		return true
	}
	return section.IncludesZero()
}

// IsFullRange returns whether this address covers the entire address space of this address version or type.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (addr *addressInternal) IsFullRange() bool {
	section := addr.section
	if section == nil {
		// when no bits, the only value 0 is the max value too
		return true
	}
	return section.IsFullRange()
}

func (addr *addressInternal) getDivisionsInternal() []*AddressDivision {
	return addr.section.getDivisionsInternal()
}

// reverseSegments returns a new address with the segments reversed.
func (addr *addressInternal) reverseSegments() *Address {
	return addr.checkIdentity(addr.section.ReverseSegments())
}

func (addr *addressInternal) equalsSameVersion(other AddressType) bool {
	otherAddr := other.ToAddressBase()
	if addr.toAddress() == otherAddr {
		return true
	} else if otherAddr == nil {
		return false
	}

	otherSection := otherAddr.GetSection()
	return addr.section.sameCountTypeEquals(otherSection) &&
		// if it it is IPv6 and has a zone, then it does not equal addresses from other zones
		addr.isSameZone(otherAddr)
}

// withoutPrefixLen returns the same address but with no associated prefix length.
func (addr *addressInternal) withoutPrefixLen() *Address {
	return addr.checkIdentity(addr.section.withoutPrefixLen())
}

func (addr *addressInternal) setPrefixLenZeroed(prefixLen BitCount) (res *Address, err address_error.IncompatibleAddressError) {
	section, err := addr.section.setPrefixLenZeroed(prefixLen)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

// assignMinPrefixForBlock constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
// such that the range of values are a set of subnet blocks for that prefix.
func (addr *addressInternal) assignMinPrefixForBlock() *Address {
	return addr.setPrefixLen(addr.GetMinPrefixLenForBlock())
}

// equivalent to section.sectionIterator
func (addr *addressInternal) addrIterator(excludeFunc func([]*AddressDivision) bool) Iterator[*Address] {
	var iterator Iterator[[]*AddressDivision]
	useOriginal := !addr.isMultiple()
	original := addr.toAddress()

	if useOriginal {
		if excludeFunc != nil && excludeFunc(addr.getDivisionsInternal()) {
			original = nil // the single-valued iterator starts out empty
		}
	} else {
		address := addr.toAddress()
		iterator = allSegmentsIterator(
			addr.getDivisionCount(),
			nil,
			func(index int) Iterator[*AddressSegment] { return address.getSegment(index).iterator() },
			excludeFunc)
	}

	return addrIterator(
		useOriginal,
		original,
		original.getPrefixLen(),
		false,
		iterator)
}

func (addr *addressInternal) blockIterator(segmentCount int) Iterator[*Address] {
	if segmentCount < 0 {
		segmentCount = 0
	}

	allSegsCount := addr.getDivisionCount()
	if segmentCount >= allSegsCount {
		return addr.addrIterator(nil)
	}

	var iterator Iterator[[]*AddressDivision]
	address := addr.toAddress()
	useOriginal := !addr.section.isMultipleTo(segmentCount)
	if !useOriginal {
		var hostSegIteratorProducer func(index int) Iterator[*AddressSegment]
		hostSegIteratorProducer = func(index int) Iterator[*AddressSegment] {
			return address.getSegment(index).identityIterator()
		}
		segIteratorProducer := func(index int) Iterator[*AddressSegment] {
			return address.getSegment(index).iterator()
		}
		iterator = segmentsIterator(
			allSegsCount,
			nil, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
			segIteratorProducer,
			nil,
			segmentCount-1,
			segmentCount,
			hostSegIteratorProducer)
	}

	return addrIterator(
		useOriginal,
		address,
		address.getPrefixLen(),
		addr.section.isMultipleFrom(segmentCount),
		iterator)
}

func (addr *addressInternal) getSequentialBlockIndex() int {
	if addr.section == nil {
		return 0
	}
	return addr.section.GetSequentialBlockIndex()
}

func (addr *addressInternal) getSequentialBlockCount() *big.Int {
	if addr.section == nil {
		return bigOne()
	}
	return addr.section.GetSequentialBlockCount()
}

func (addr *addressInternal) getSegmentStrings() []string {
	return addr.section.getSegmentStrings()
}

// sequentialBlockIterator iterates through the minimal number of maximum-sized blocks comprising this subnet
// a block is sequential if given any two addresses in the block, any intervening address between the two is also in the block
func (addr *addressInternal) sequentialBlockIterator() Iterator[*Address] {
	return addr.blockIterator(addr.getSequentialBlockIndex())
}

// Address represents a single address or a set of multiple addresses, such as an IP subnet or a set of MAC addresses.
//
// Addresses consist of a sequence of segments, each with the same bit-size.
// The number of such segments and the bit-size are determined by the underlying version or type of address, whether IPv4, IPv6, MAC, or other.
// Each segment can represent a single value or a sequential range of values.
// Addresses can also have an appropriate prefix length - the number of consecutive bits that make up the prefix, the most significant bits of the address.
//
// To create an address from a string, use NewIPAddressString or NewMACAddressString,
// then use the ToAddress or GetAddress methods to get [IPAddress] or [MACAddress] and then you can convert it to that type using the ToAddressBase method.
//
// Any specific address types can be converted to Address using the ToAddressBase method
// and then returned to the original types using methods such as ToIPv6, ToIP, ToIPv4 and ToMAC.
// When such a method is called for a given address,
// if the address was not originally constructed as the type returned by the method, the method will return nil.
// Conversion methods work with nil pointers (return nil), so they can be safely chained together.
//
// This allows you to create polymorphic code that works with all addresses, like the address triplet code in this library,
// while at the same time allowing methods and code specific to each version or address type.
//
// You can also use the IsIPv6, IsIP, IsIPv4 and IsMAC methods,
// which will return true if and only if the corresponding ToIPv6, ToIP, ToIPv4 and ToMAC methods return non-nil, respectively.
//
// A zero value for an address is an address with no segments and no associated version or type of address, also known as adaptive zero.
type Address struct {
	addressInternal
}

// GetLower returns the address in the subnet or address collection with the lowest numeric value,
// which will be the receiver if it represents a single address.
// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
func (addr *Address) GetLower() *Address {
	return addr.init().getLower()
}

// GetUpper returns the address in the subnet or address collection with the highest numeric value,
// which will be the receiver if it represents a single address.
// For example, for the subnet "1.2-3.4.5-6", the address "1.3.4.6" is returned.
func (addr *Address) GetUpper() *Address {
	return addr.init().getUpper()
}

// ToPrefixBlock returns the address collection associated with the prefix of this address or address collection,
// the address whose prefix matches the prefix of this address, and the remaining bits span all values.
// If this address has no prefix length, this address is returned.
//
// The returned address collection will include all addresses with the same prefix as this one, the prefix "block".
func (addr *Address) ToPrefixBlock() *Address {
	return addr.init().toPrefixBlock()
}

// ToPrefixBlockLen returns the address associated with the prefix length provided,
// the address collection whose prefix of that length matches the prefix of this address, and the remaining bits span all values.
//
// The returned address will include all addresses with the same prefix as this one, the prefix "block".
func (addr *Address) ToPrefixBlockLen(prefLen BitCount) *Address {
	return addr.init().toPrefixBlockLen(prefLen)
}

// ToBlock creates a new block of addresses by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr *Address) ToBlock(segmentIndex int, lower, upper SegInt) *Address {
	return addr.init().toBlock(segmentIndex, lower, upper)
}

func (addr *Address) init() *Address {
	if addr.section == nil {
		return zeroAddr // this has a zero section rather that a nil section
	}
	return addr
}

// IsIP returns true if this address or subnet originated as an IPv4 or IPv6 address or subnet,
// or an implicitly zero-valued IP.
// If so, use ToIP to convert back to the IP-specific type.
func (addr *Address) IsIP() bool {
	return addr != nil && addr.isIP()
}

// ToIP converts to an IPAddress if this address or subnet originated as an IPv4 or IPv6 address or subnet, or an implicitly zero-valued IP.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *Address) ToIP() *IPAddress {
	if addr.IsIP() {
		return (*IPAddress)(unsafe.Pointer(addr))
	}
	return nil
}

// GetSection returns the backing section for this address or subnet, comprising all segments.
func (addr *Address) GetSection() *AddressSection {
	return addr.init().section
}

// IsIPv4 returns true if this address or subnet originated as an IPv4 address or subnet.
// If so, use ToIPv4 to convert back to the IPv4-specific type.
func (addr *Address) IsIPv4() bool {
	return addr != nil && addr.isIPv4()
}

// ToIPv4 converts to an IPv4Address if this address or subnet originated as an IPv4 address or subnet.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr *Address) ToIPv4() *IPv4Address {
	if addr.IsIPv4() {
		return (*IPv4Address)(unsafe.Pointer(addr))
	}
	return nil
}

// IsIPv6 returns true if this address or subnet originated as an IPv6 address or subnet.  If so, use ToIPv6 to convert back to the IPv6-specific type.
func (addr *Address) IsIPv6() bool {
	return addr != nil && addr.isIPv6()
}

// ToIPv6 converts to an IPv6Address if this address or subnet originated as an IPv6 address or subnet.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *Address) ToIPv6() *IPv6Address {
	if addr.IsIPv6() {
		return (*IPv6Address)(unsafe.Pointer(addr))
	}
	return nil
}

// IsMAC returns true if this address or address collection originated as a MAC address or address collection.
// If so, use ToMAC to convert back to the MAC-specific type.
func (addr *Address) IsMAC() bool {
	return addr != nil && addr.isMAC()
}

// ToMAC converts to a MACAddress if this address or subnet originated as a MAC address or subnet.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *Address) ToMAC() *MACAddress {
	if addr.IsMAC() {
		return (*MACAddress)(addr)
	}
	return nil
}

// ToAddressBase is an identity method.
//
// ToAddressBase can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (addr *Address) ToAddressBase() *Address {
	return addr
}

// Bytes returns the lowest address in this subnet or address collection as a byte slice.
func (addr *Address) Bytes() []byte {
	return addr.init().section.Bytes()
}

// UpperBytes returns the highest address in this subnet or address collection as a byte slice.
func (addr *Address) UpperBytes() []byte {
	return addr.init().section.UpperBytes()
}

// toAddressBase is needed for tries
func (addr *Address) toAddressBase() *Address {
	return addr
}

// TestBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the least significant bit.
// In other words, it computes (bits & (1 << n)) != 0), using the lower value of this address.
// TestBit will panic if n < 0, or if it matches or exceeds the bit count of this item.
func (addr *Address) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// IsOneBit returns true if the bit in the lower value of this address at the given index is 1, where index 0 refers to the most significant bit.
// IsOneBit will panic if bitIndex is less than zero, or if it is larger than the bit count of this item.
func (addr *Address) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

// GetCount returns the count of addresses that this address or subnet represents.
//
// If just a single address, not a collection nor subnet of multiple addresses, returns 1.
//
// For instance, the IP address subnet "2001:db8::/64" has the count of 2 to the power of 64.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (addr *Address) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

// IsMultiple returns true if this represents more than a single individual address, whether it is a collection or subnet of multiple addresses.
func (addr *Address) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

// IsPrefixed returns whether this address has an associated prefix length.
func (addr *Address) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (addr *Address) GetTrailingSection(index int) *AddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (addr *Address) GetSubSection(index, endIndex int) *AddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
func (addr *Address) CopySubSegments(start, end int, segs []*AddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySegments copies the existing segments into the given slice,
// as much as can be fit into the slice, returning the number of segments copied.
func (addr *Address) CopySegments(segs []*AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (addr *Address) GetSegments() []*AddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index.
// The first segment is at index 0.
// GetSegment will panic given a negative index or an index matching or larger than the segment count.
func (addr *Address) GetSegment(index int) *AddressSegment {
	return addr.getSegment(index)
}

// GetSegmentCount returns the segment count, the number of segments in this address.
// For example, IPv4 addresses have 4, IPv6 addresses have 8.
func (addr *Address) GetSegmentCount() int {
	return addr.getDivisionCount()
}

// ForEachSegment visits each segment in order from most-significant to least, the most significant with index 0,
// calling the given function for each, terminating early if the function returns true.
// Returns the number of visited segments.
func (addr *Address) ForEachSegment(consumer func(segmentIndex int, segment *AddressSegment) (stop bool)) int {
	return addr.GetSection().ForEachSegment(consumer)
}

// GetDivisionCount returns the division count, which is the same as the segment count, since the divisions of an address are the segments.
func (addr *Address) GetDivisionCount() int {
	return addr.getDivisionCount()
}

// GetValue returns the lowest address in this subnet or address collection as an integer value.
func (addr *Address) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

// GetUpperValue returns the highest address in this subnet or address collection as an integer value.
func (addr *Address) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

// CopyBytes copies the value of the lowest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *Address) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

// CopyUpperBytes copies the value of the highest individual address in the subnet into a byte slice.
//
// If the value can fit in the given slice, the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (addr *Address) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

// IsMax returns whether this address matches exactly the maximum possible value, the address whose bits are all ones.
func (addr *Address) IsMax() bool {
	return addr.init().section.IsMax()
}

// IncludesMax returns whether this address includes the max address, the address whose bits are all ones, within its range.
func (addr *Address) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}
