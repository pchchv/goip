package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

// WrappedIPAddress is the implementation of ExtendedIPSegmentSeries for IP addresses.
type WrappedIPAddress struct {
	*IPAddress
}

// GetSection returns the backing section for this series, comprising all segments.
func (addr WrappedIPAddress) GetSection() *IPAddressSection {
	return addr.IPAddress.GetSection()
}

// SequentialBlockIterator iterates through the sequential series that make up this series.
//
// Practically, this means finding the count of segments for which the segments that follow are not full range,
// and then using BlockIterator with that segment count.
//
// Use GetSequentialBlockCount to get the number of iterated elements.
func (addr WrappedIPAddress) SequentialBlockIterator() Iterator[ExtendedIPSegmentSeries] {
	return ipaddressSeriesIterator{addr.IPAddress.SequentialBlockIterator()}
}

// BlockIterator Iterates through the series that can be obtained
// by iterating through all the upper segments up to the given segment count.
// The segments following remain the same in all iterated series.
func (addr WrappedIPAddress) BlockIterator(segmentCount int) Iterator[ExtendedIPSegmentSeries] {
	return ipaddressSeriesIterator{addr.IPAddress.BlockIterator(segmentCount)}
}

// Iterator provides an iterator to iterate through the individual series of this series.
//
// When iterating, the prefix length is preserved.
// Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual series.
//
// Call IsMultiple to determine if this instance represents multiple series,
// or GetCount for the count.
func (addr WrappedIPAddress) Iterator() Iterator[ExtendedIPSegmentSeries] {
	return ipaddressSeriesIterator{addr.IPAddress.Iterator()}
}

// ToZeroHostLen converts the subnet to one in which all individual addresses have a host of zero,
// the host being the bits following the given prefix length.
// If this address has the same prefix length,
// then the returned one will too, otherwise the returned series will have no prefix length.
//
// This returns an error if the subnet is a range which cannot be converted to
// a range in which all addresses have zero hosts,
// because the conversion results in a segment that is not a sequential range of values.
func (addr WrappedIPAddress) ToZeroHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToZeroHostLen(bitCount)) //in IPAddress/Section
}

// ToZeroHost converts the subnet to one in which all individual addresses have a host of zero,
// the host being the bits following the prefix length.
// If the subnet has no prefix length, then it returns an all-zero series.
//
// The returned series will have the same prefix length.
//
// For instance, the zero host of "1.2.3.4/16" is the individual address "1.2.0.0/16".
//
// This returns an error if the series is a range which cannot be converted to
// a range in which all individual elements have zero hosts,
// because the conversion results in a series segment that is not a sequential range of values.
func (addr WrappedIPAddress) ToZeroHost() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToZeroHost()) // in IPAddress/Section/Segment
}

// ToMaxHostLen converts the address or subnet to one in which all individual addresses have a host of all one-bits, the max host,
// the host being the bits following the given prefix length.
// If this address or subnet has the same prefix length,
// then the resulting one will too, otherwise the resulting series will have no prefix length.
//
// For instance, the zero host of "1.2.3.4" for the prefix length of 16 is the address "1.2.255.255".
//
// This returns an error if the address or subnet is a range which cannot be converted to
// a range in which all individual addresses have max hosts,
// because the conversion results in a series segment that is not a sequential range of values.
func (addr WrappedIPAddress) ToMaxHostLen(bitCount BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToMaxHostLen(bitCount))
}

// ToMaxHost converts the subnet to one in which all individual addresses have a host of all one-bits, the max value,
// the host being the bits following the prefix length.
// If the subnet has no prefix length, then it returns an all-ones address, the max address.
//
// The returned series will have the same prefix length.
//
// For instance, the max host of "1.2.3.4/16" gives the broadcast address "1.2.255.255/16".
//
// This returns an error if the series is a range which cannot be converted to
// a range in which all individual elements have max hosts,
// because the conversion results in a series segment that is not a sequential range of values.
func (addr WrappedIPAddress) ToMaxHost() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ToMaxHost())
}

// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this series.
// The returned block will have an assigned prefix length indicating the prefix length for the block.
//
// There may be no such series - it is required that the range of values match the range of a prefix block.
// If there is no such series, then nil is returned.
func (addr WrappedIPAddress) AssignPrefixForSingleBlock() ExtendedIPSegmentSeries {
	return convIPAddrToIntf(addr.IPAddress.AssignPrefixForSingleBlock())
}

// SpanWithPrefixBlocks returns an array of prefix blocks
// that spans the same set of individual series as this subnet.
func (addr WrappedIPAddress) SpanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	return addr.IPAddress.spanWithPrefixBlocks()
}

// SpanWithSequentialBlocks produces the smallest slice of sequential blocks
// that cover the same set of individual addresses as this subnet.
//
// This slice can be shorter than that produced by SpanWithPrefixBlocks and is never longer.
func (addr WrappedIPAddress) SpanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	return addr.IPAddress.spanWithSequentialBlocks()
}

// CoverWithPrefixBlock returns the minimal-size prefix block that covers all the addresses in this subnet.
// The resulting block will have a larger subnet size than this,
// unless this series is already a prefix block.
func (addr WrappedIPAddress) CoverWithPrefixBlock() ExtendedIPSegmentSeries {
	return addr.IPAddress.coverSeriesWithPrefixBlock()
}

// SetPrefixLenZeroed sets the prefix length.
//
// A prefix length will not be set to a value lower than zero or beyond the bit length of the series.
// The provided prefix length will be adjusted to these boundaries if necessary.
//
// If this series has a prefix length, and the prefix length is increased when setting the new prefix length,
// the bits moved within the prefix become zero.
// If this series has a prefix length, and the prefix length is decreased when setting the new prefix length,
// the bits moved outside the prefix become zero.
//
// In other words, bits that move from one side of the prefix length to the other
// (bits moved into the prefix or outside the prefix) are zeroed.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr WrappedIPAddress) SetPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.SetPrefixLenZeroed(prefixLen))
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by
// the given increment while zeroing out the bits that have moved into or outside the prefix.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
//
// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
//
// When prefix length is increased, the bits moved within the prefix become zero.
// When a prefix length is decreased, the bits moved outside the prefix become zero.
//
// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
func (addr WrappedIPAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.AdjustPrefixLenZeroed(prefixLen))
}

// ReverseBytes returns a new segment series with the bytes reversed.  Any prefix length is dropped.
//
// If each segment is more than 1 byte long, and the bytes within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, then this returns an error.
//
// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
func (addr WrappedIPAddress) ReverseBytes() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ReverseBytes())
}

// ReverseBits returns a new segment series with the bits reversed.  Any prefix length is dropped.
//
// If the bits within a single segment cannot be reversed because the segment represents a range,
// and reversing the segment values results in a range that is not contiguous, this returns an error.
//
// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (addr WrappedIPAddress) ReverseBits(perByte bool) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapIPAddrWithErr(addr.IPAddress.ReverseBits(perByte))
}

// Unwrap returns the wrapped address as an interface, IPAddressSegmentSeries.
func (addr WrappedIPAddress) Unwrap() IPAddressSegmentSeries {
	res := addr.IPAddress
	if res == nil {
		return nil
	}
	return res
}

// ToIPv4 converts to an IPv4AddressSegmentSeries if this address originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr WrappedIPAddress) ToIPv4() IPv4AddressSegmentSeries {
	return addr.IPAddress.ToIPv4()
}

// ToIPv6 converts to an IPv6AddressSegmentSeries if this address originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr WrappedIPAddress) ToIPv6() IPv6AddressSegmentSeries {
	return addr.IPAddress.ToIPv6()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
//
// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr WrappedIPAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedIPSegmentSeries {
	return wrapIPAddress(addr.IPAddress.AdjustPrefixLen(prefixLen))
}

// ReverseSegments returns a new series with the segments reversed.
func (addr WrappedIPAddress) ReverseSegments() ExtendedIPSegmentSeries {
	return wrapIPAddress(addr.IPAddress.ReverseSegments())
}

// ExtendedIPSegmentSeries wraps either an [IPAddress] or [IPAddressSection].
// ExtendedIPSegmentSeries can be used to write code that works with both IP addresses and IP address sections,
// going further than [IPAddressSegmentSeries] to offer additional methods, methods with the series types in their signature.
type ExtendedIPSegmentSeries interface {
	IPAddressSegmentSeries
	// Unwrap returns the wrapped IP address or IP address section as an interface, IPAddressSegmentSeries.
	Unwrap() IPAddressSegmentSeries
	// Equal returns whether the given address series is equal to this address series.
	// Two address series are equal if they represent the same set of series.
	// Both must be equal addresses or both must be equal sections.
	Equal(ExtendedIPSegmentSeries) bool
	// Contains returns whether this is same type and version as the
	// given address series and whether it contains all values in the given series.
	//
	// Series must also have the same number of segments to be comparable, otherwise false is returned.
	Contains(ExtendedIPSegmentSeries) bool
	// GetSection returns the backing section for this series, comprising all segments.
	GetSection() *IPAddressSection
	// GetTrailingSection returns an ending subsection of the full address section.
	GetTrailingSection(index int) *IPAddressSection
	// GetSubSection returns a subsection of the full address section.
	GetSubSection(index, endIndex int) *IPAddressSection
	// GetNetworkSection returns an address section containing the segments with the network of the series, the prefix bits.
	// The returned section will have only as many segments as needed as determined by the existing CIDR network prefix length.
	//
	// If this series has no CIDR prefix length, the returned network section will
	// be the entire series as a prefixed section with prefix length matching the address bit length.
	GetNetworkSection() *IPAddressSection
	// GetHostSection returns a section containing the segments with the host of the series,
	// the bits beyond the CIDR network prefix length.
	// The returned section will have only as many segments as needed to contain the host.
	//
	// If this series has no prefix length, the returned host section will be the full section.
	GetHostSection() *IPAddressSection
	// GetNetworkSectionLen returns a section containing the segments with the network of the series,
	// the prefix bits according to the given prefix length.
	// The returned section will have only as many segments as needed to contain the network.
	//
	// The new section will be assigned the given prefix length,
	// unless the existing prefix length is smaller, in which case the existing prefix length will be retained.
	GetNetworkSectionLen(BitCount) *IPAddressSection
	// GetHostSectionLen returns a section containing the segments with the host of the series,
	// the bits beyond the given CIDR network prefix length.
	// The returned section will have only as many segments as needed to contain the host.
	GetHostSectionLen(BitCount) *IPAddressSection
	// GetNetworkMask returns the network mask associated with the CIDR network prefix length of this series.
	// If this series has no prefix length, then the all-ones mask is returned.
	GetNetworkMask() ExtendedIPSegmentSeries
	// GetHostMask returns the host mask associated with the CIDR network prefix length of this series.
	// If this series has no prefix length, then the all-ones mask is returned.
	GetHostMask() ExtendedIPSegmentSeries
	// GetSegment returns the segment at the given index.
	// The first segment is at index 0.
	// GetSegment will panic given a negative index or an index matching or larger than the segment count.
	GetSegment(index int) *IPAddressSegment
	// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
	GetSegments() []*IPAddressSegment
	// CopySegments copies the existing segments into the given slice,
	// as much as can be fit into the slice, returning the number of segments copied.
	CopySegments(segs []*IPAddressSegment) (count int)
	// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
	// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
	CopySubSegments(start, end int, segs []*IPAddressSegment) (count int)
	// IsIPv4 returns true if this series originated as an IPv4 series.
	// If so, use ToIPv4 to convert back to the IPv4-specific type.
	IsIPv4() bool
	// IsIPv6 returns true if this series originated as an IPv6 series.
	// If so, use ToIPv6 to convert back to the IPv6-specific type.
	IsIPv6() bool
	// ToIPv4 converts to an IPv4AddressSegmentSeries if this series originated as an IPv4 series.
	// If not, ToIPv4 returns nil.
	//
	// ToIPv4 implementations can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
	ToIPv4() IPv4AddressSegmentSeries
	// ToIPv6 converts to an IPv4AddressSegmentSeries if this series originated as an IPv6 series.
	// If not, ToIPv6 returns nil.
	//
	// ToIPv6 implementations can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
	ToIPv6() IPv6AddressSegmentSeries
	// ToBlock creates a new series block by changing the segment at the given index to have the given lower and upper value,
	// and changing the following segments to be full-range.
	ToBlock(segmentIndex int, lower, upper SegInt) ExtendedIPSegmentSeries
	// ToPrefixBlock returns the series with the same prefix as this series while the remaining bits span all values.
	// The series will be the block of all series with the same prefix.
	//
	// If this series has no prefix, this series is returned.
	ToPrefixBlock() ExtendedIPSegmentSeries
	// ToPrefixBlockLen returns the series with the same prefix of the given length as this series while the remaining bits span all values.
	// The returned series will be the block of all series with the same prefix.
	ToPrefixBlockLen(BitCount) ExtendedIPSegmentSeries
	// ToZeroHostLen converts the series to one in which all individual series have a host of zero,
	// the host being the bits following the given prefix length.
	// If this series has the same prefix length, then the returned one will too, otherwise the returned series will have no prefix length.
	//
	// This returns an error if the series is a range which cannot be converted to a range in which all series have zero hosts,
	// because the conversion results in a segment that is not a sequential range of values.
	ToZeroHostLen(BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ToZeroHost converts the series to one in which all individual series have a host of zero,
	// the host being the bits following the prefix length.
	// If the series has no prefix length, then it returns an all-zero series.
	//
	// The returned series will have the same prefix length.
	//
	// For instance, the zero host of "1.2.3.4/16" is the individual address "1.2.0.0/16".
	//
	// This returns an error if the series is a range which cannot be converted to a range in which all individual elements have zero hosts,
	// because the conversion results in a series segment that is not a sequential range of values.
	ToZeroHost() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ToMaxHostLen converts the series to one in which all individual series have a host of all one-bits, the max host,
	// the host being the bits following the given prefix length.
	// If this series has the same prefix length, then the resulting series will too, otherwise the resulting series will have no prefix length.
	//
	// For instance, the zero host of "1.2.3.4" for the prefix length of 16 is the address "1.2.255.255".
	//
	// This returns an error if the series is a range which cannot be converted to a range in which all individual elements have max hosts,
	// because the conversion results in a series segment that is not a sequential range of values.
	ToMaxHostLen(BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ToMaxHost converts the series to one in which all individual series have a host of all one-bits, the max value,
	// the host being the bits following the prefix length.
	// If the series has no prefix length, then it returns an all-ones series, the max series.
	//
	// The returned series will have the same prefix length.
	//
	// For instance, the max host of "1.2.3.4/16" gives the broadcast address "1.2.255.255/16".
	//
	// This returns an error if the series is a range which cannot be converted to a range in which all individual elements have max hosts,
	// because the conversion results in a series segment that is not a sequential range of values.
	ToMaxHost() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ToZeroNetwork converts the series to one in which all individual addresses or address sections have a network of zero,
	// the network being the bits within the prefix length.
	// If the series has no prefix length, then it returns an all-zero series.
	//
	// The returned series will have the same prefix length.
	ToZeroNetwork() ExtendedIPSegmentSeries
	// Increment returns the item that is the given increment upwards into the range,
	// with the increment of 0 returning the first in the range.
	//
	// If the increment i matches or exceeds the range count c, then i - c + 1
	// is added to the upper item of the range.
	// An increment matching the count gives you the item just above the highest in the range.
	//
	// If the increment is negative, it is added to the lowest of the range.
	// To get the item just below the lowest of the range, use the increment -1.
	//
	// If this represents just a single value, the item is simply incremented by the given increment, positive or negative.
	//
	// If this item represents multiple values, a positive increment i is equivalent i + 1 values from the iterator and beyond.
	// For instance, a increment of 0 is the first value from the iterator, an increment of 1 is the second value from the iterator, and so on.
	// An increment of a negative value added to the count is equivalent to the same number of iterator values preceding the last value of the iterator.
	// For instance, an increment of count - 1 is the last value from the iterator, an increment of count - 2 is the second last value, and so on.
	//
	// On overflow or underflow, Increment returns nil.
	Increment(int64) ExtendedIPSegmentSeries
	// IncrementBoundary returns the item that is the given increment from the range boundaries of this item.
	//
	// If the given increment is positive, adds the value to the highest (GetUpper) in the range to produce a new item.
	// If the given increment is negative, adds the value to the lowest (GetLower) in the range to produce a new item.
	// If the increment is zero, returns this.
	//
	// If this represents just a single value, this item is simply incremented by the given increment value, positive or negative.
	//
	// On overflow or underflow, IncrementBoundary returns nil.
	IncrementBoundary(int64) ExtendedIPSegmentSeries
	// GetLower returns the series in the range with the lowest numeric value,
	// which will be the same series if it represents a single value.
	// For example, for "1.2-3.4.5-6", the series "1.2.4.5" is returned.
	GetLower() ExtendedIPSegmentSeries
	// GetUpper returns the series in the range with the highest numeric value,
	// which will be the same series if it represents a single value.
	// For example, for the subnet "1.2-3.4.5-6", the address "1.3.4.6" is returned.
	GetUpper() ExtendedIPSegmentSeries
	// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this series.
	// The returned block will have an assigned prefix length indicating the prefix length for the block.
	//
	// There may be no such series - it is required that the range of values match the range of a prefix block.
	// If there is no such series, then nil is returned.
	AssignPrefixForSingleBlock() ExtendedIPSegmentSeries
	// AssignMinPrefixForBlock returns an equivalent series, assigned the smallest prefix length possible,
	// such that the prefix block for that prefix length is in this series.
	//
	// In other words, this method assigns a prefix length to this series matching the largest prefix block in this series.
	AssignMinPrefixForBlock() ExtendedIPSegmentSeries
	// Iterator provides an iterator to iterate through the individual series of this series.
	//
	// When iterating, the prefix length is preserved.  Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual series.
	//
	// Call IsMultiple to determine if this instance represents multiple series, or GetCount for the count.
	Iterator() Iterator[ExtendedIPSegmentSeries]
	// PrefixIterator provides an iterator to iterate through the individual prefixes of this series,
	// each iterated element spanning the range of values for its prefix.
	//
	// It is similar to the prefix block iterator, except for possibly the first and last iterated elements, which might not be prefix blocks,
	// instead constraining themselves to values from this series.
	//
	// If the series has no prefix length, then this is equivalent to Iterator.
	PrefixIterator() Iterator[ExtendedIPSegmentSeries]
	// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks, one for each prefix of this series.
	// Each iterated series will be a prefix block with the same prefix length as this series.
	//
	// If this series has no prefix length, then this is equivalent to Iterator.
	PrefixBlockIterator() Iterator[ExtendedIPSegmentSeries]
	// SequentialBlockIterator iterates through the sequential series that make up this series.
	//
	// Practically, this means finding the count of segments for which the segments that follow are not full range, and then using BlockIterator with that segment count.
	//
	// Use GetSequentialBlockCount to get the number of iterated elements.
	SequentialBlockIterator() Iterator[ExtendedIPSegmentSeries]
	// BlockIterator Iterates through the series that can be obtained by iterating through all the upper segments up to the given segment count.
	// The segments following remain the same in all iterated series.
	BlockIterator(segmentCount int) Iterator[ExtendedIPSegmentSeries]
	// SpanWithPrefixBlocks returns an array of prefix blocks that spans the same set of individual series as this address series.
	SpanWithPrefixBlocks() []ExtendedIPSegmentSeries
	// SpanWithSequentialBlocks produces the smallest slice of sequential blocks that cover the same set of individual series as this series.
	//
	// This slice can be shorter than that produced by SpanWithPrefixBlocks and is never longer.
	SpanWithSequentialBlocks() []ExtendedIPSegmentSeries
	// CoverWithPrefixBlock returns the minimal-size prefix block that covers all the values in this series.
	// The resulting block will have a larger series count than this, unless this series is already a prefix block.
	CoverWithPrefixBlock() ExtendedIPSegmentSeries
	// AdjustPrefixLen increases or decreases the prefix length by the given increment.
	//
	// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
	//
	// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
	// or it will be set to the adjustment added to the bit count if negative.
	AdjustPrefixLen(BitCount) ExtendedIPSegmentSeries
	// AdjustPrefixLenZeroed increases or decreases the prefix length by the given increment while zeroing out the bits that have moved into or outside the prefix.
	//
	// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
	//
	// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
	// or it will be set to the adjustment added to the bit count if negative.
	//
	// When prefix length is increased, the bits moved within the prefix become zero.
	// When a prefix length is decreased, the bits moved outside the prefix become zero.
	//
	// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
	AdjustPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// SetPrefixLen sets the prefix length.
	//
	// A prefix length will not be set to a value lower than zero or beyond the bit length of the series.
	// The provided prefix length will be adjusted to these boundaries if necessary.
	SetPrefixLen(BitCount) ExtendedIPSegmentSeries
	// SetPrefixLenZeroed sets the prefix length.
	//
	// A prefix length will not be set to a value lower than zero or beyond the bit length of the series.
	// The provided prefix length will be adjusted to these boundaries if necessary.
	//
	// If this series has a prefix length, and the prefix length is increased when setting the new prefix length, the bits moved within the prefix become zero.
	// If this series has a prefix length, and the prefix length is decreased when setting the new prefix length, the bits moved outside the prefix become zero.
	//
	// In other words, bits that move from one side of the prefix length to the other (bits moved into the prefix or outside the prefix) are zeroed.
	//
	// If the result cannot be zeroed because zeroing out bits results in a non-contiguous segment, an error is returned.
	SetPrefixLenZeroed(BitCount) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// WithoutPrefixLen provides the same address series but with no prefix length.  The values remain unchanged.
	WithoutPrefixLen() ExtendedIPSegmentSeries
	// ReverseBytes returns a new segment series with the bytes reversed.  Any prefix length is dropped.
	//
	// If each segment is more than 1 byte long, and the bytes within a single segment cannot be reversed because the segment represents a range,
	// and reversing the segment values results in a range that is not contiguous, then this returns an error.
	//
	// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
	ReverseBytes() (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ReverseBits returns a new segment series with the bits reversed.  Any prefix length is dropped.
	//
	// If the bits within a single segment cannot be reversed because the segment represents a range,
	// and reversing the segment values results in a range that is not contiguous, this returns an error.
	//
	// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
	//
	// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
	ReverseBits(perByte bool) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError)
	// ReverseSegments returns a new series with the segments reversed.
	ReverseSegments() ExtendedIPSegmentSeries
	// ToCustomString creates a customized string from this series according to the given string option parameters.
	ToCustomString(stringOptions address_string.IPStringOptions) string
}

// WrappedIPAddressSection is the implementation of ExtendedIPSegmentSeries for IP address sections.
type WrappedIPAddressSection struct {
	*IPAddressSection
}

// GetSection returns the backing section for this series, comprising all segments.
func (section WrappedIPAddressSection) GetSection() *IPAddressSection {
	return section.IPAddressSection
}

// Contains returns whether this is same type and version as
// the given address series and whether it contains all values in the given series.
//
// Series must also have the same number of segments to be comparable, otherwise false is returned.
func (section WrappedIPAddressSection) Contains(other ExtendedIPSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.IPAddressSection.Contains(s)
}

// Equal returns whether the given address series is equal to this address series.
// Two address series are equal if they represent the same set of series.
// Both must be equal sections.
func (section WrappedIPAddressSection) Equal(other ExtendedIPSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.IPAddressSection.Equal(s)
}

// ToIPv4 converts to an IPv4AddressSegmentSeries if this section originated as an IPv4 section.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section WrappedIPAddressSection) ToIPv4() IPv4AddressSegmentSeries {
	return section.IPAddressSection.ToIPv4()
}

// ToIPv6 converts to an IPv6AddressSegmentSeries if this section originated as an IPv6 section.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (section WrappedIPAddressSection) ToIPv6() IPv6AddressSegmentSeries {
	return section.IPAddressSection.ToIPv6()
}

// GetNetworkMask returns the network mask associated with the CIDR network prefix length of this address section.
// If this series has no prefix length, then the all-ones mask is returned.
func (section WrappedIPAddressSection) GetNetworkMask() ExtendedIPSegmentSeries {
	return wrapIPSection(section.IPAddressSection.GetNetworkMask())
}

// GetHostMask returns the host mask associated with the CIDR network prefix length of this address section.
// If this series has no prefix length, then the all-ones mask is returned.
func (section WrappedIPAddressSection) GetHostMask() ExtendedIPSegmentSeries {
	return wrapIPSection(section.IPAddressSection.GetHostMask())
}

// Unwrap returns the wrapped address section as an interface, IPAddressSegmentSeries.
func (section WrappedIPAddressSection) Unwrap() IPAddressSegmentSeries {
	res := section.IPAddressSection
	if res == nil {
		return nil
	}
	return res
}

// SequentialBlockIterator iterates through the sequential series that make up this series.
//
// Practically, this means finding the count of segments for which the segments that follow are not full range,
// and then using BlockIterator with that segment count.
//
// Use GetSequentialBlockCount to get the number of iterated elements.
func (section WrappedIPAddressSection) SequentialBlockIterator() Iterator[ExtendedIPSegmentSeries] {
	return ipSectionSeriesIterator{section.IPAddressSection.SequentialBlockIterator()}
}

// BlockIterator Iterates through the series that can be obtained by iterating through all the upper segments up to the given segment count.
// The segments following remain the same in all iterated series.
func (section WrappedIPAddressSection) BlockIterator(segmentCount int) Iterator[ExtendedIPSegmentSeries] {
	return ipSectionSeriesIterator{section.IPAddressSection.BlockIterator(segmentCount)}
}

// Iterator provides an iterator to iterate through the individual series of this series.
//
// When iterating, the prefix length is preserved.  Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual series.
//
// Call IsMultiple to determine if this instance represents multiple series, or GetCount for the count.
func (section WrappedIPAddressSection) Iterator() Iterator[ExtendedIPSegmentSeries] {
	return ipSectionSeriesIterator{section.IPAddressSection.Iterator()}
}

// PrefixIterator provides an iterator to iterate through the individual prefixes of this series,
// each iterated element spanning the range of values for its prefix.
//
// It is similar to the prefix block iterator, except for possibly the first and last iterated elements, which might not be prefix blocks,
// instead constraining themselves to values from this series.
//
// If the series has no prefix length, then this is equivalent to Iterator.
func (section WrappedIPAddressSection) PrefixIterator() Iterator[ExtendedIPSegmentSeries] {
	return ipSectionSeriesIterator{section.IPAddressSection.PrefixIterator()}
}

// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks, one for each prefix of this series.
// Each iterated series will be a prefix block with the same prefix length as this series.
//
// If this series has no prefix length, then this is equivalent to Iterator.
func (section WrappedIPAddressSection) PrefixBlockIterator() Iterator[ExtendedIPSegmentSeries] {
	return ipSectionSeriesIterator{section.IPAddressSection.PrefixBlockIterator()}
}

func wrapIPAddress(addr *IPAddress) WrappedIPAddress {
	return WrappedIPAddress{addr}
}

func wrapIPSection(section *IPAddressSection) WrappedIPAddressSection {
	return WrappedIPAddressSection{section}
}

func wrapIPSectWithErr(section *IPAddressSection, err address_error.IncompatibleAddressError) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	if err == nil {
		return wrapIPSection(section), nil
	}
	return nil, err
}

func wrapIPAddrWithErr(addr *IPAddress, err address_error.IncompatibleAddressError) (ExtendedIPSegmentSeries, address_error.IncompatibleAddressError) {
	if err == nil {
		return wrapIPAddress(addr), nil
	}
	return nil, err
}

// In go, a nil value is not converted to a nil interface,
// it is converted to a non-nil interface instance with underlying value nil
func convIPAddrToIntf(addr *IPAddress) ExtendedIPSegmentSeries {
	if addr == nil {
		return nil
	}
	return wrapIPAddress(addr)
}

func convIPSectToIntf(sect *IPAddressSection) ExtendedIPSegmentSeries {
	if sect == nil {
		return nil
	}
	return wrapIPSection(sect)
}
