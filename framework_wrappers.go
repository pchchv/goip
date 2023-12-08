package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

// ExtendedSegmentSeries wraps either an Address or AddressSection.
// ExtendedSegmentSeries can be used to write code that works with both addresses and address sections,
// going further than AddressSegmentSeries to offer additional methods with the series types in their signature.
type ExtendedSegmentSeries interface {
	AddressSegmentSeries
	// Unwrap returns the wrapped address or address section as an interface, AddressSegmentSeries.
	Unwrap() AddressSegmentSeries
	// Equal returns whether the given address series is equal to this address series.
	// Two address series are equal if they represent the same set of series.
	// Both must be equal addresses or both must be equal sections.
	Equal(ExtendedSegmentSeries) bool
	// Contains returns whether this is same type and version as the given address series and whether it contains all values in the given series.
	//
	// Series must also have the same number of segments to be comparable, otherwise false is returned.
	Contains(ExtendedSegmentSeries) bool
	// GetSection returns the backing section for this series, comprising all segments.
	GetSection() *AddressSection
	// GetTrailingSection returns an ending subsection of the full address section.
	GetTrailingSection(index int) *AddressSection
	// GetSubSection returns a subsection of the full address section.
	GetSubSection(index, endIndex int) *AddressSection
	// GetSegment returns the segment at the given index.
	// The first segment is at index 0.
	// GetSegment will panic given a negative index or an index matching or larger than the segment count.
	GetSegment(index int) *AddressSegment
	// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
	GetSegments() []*AddressSegment
	// CopySegments copies the existing segments into the given slice,
	// as much as can be fit into the slice, returning the number of segments copied.
	CopySegments(segs []*AddressSegment) (count int)
	// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
	// into the given slice, as much as can be fit into the slice, returning the number of segments copied.
	CopySubSegments(start, end int, segs []*AddressSegment) (count int)
	// IsIP returns true if this series originated as an IPv4 or IPv6 series, or a zero-length IP series.  If so, use ToIP to convert back to the IP-specific type.
	IsIP() bool
	// IsIPv4 returns true if this series originated as an IPv4 series.  If so, use ToIPv4 to convert back to the IPv4-specific type.
	IsIPv4() bool
	// IsIPv6 returns true if this series originated as an IPv6 series.  If so, use ToIPv6 to convert back to the IPv6-specific type.
	IsIPv6() bool
	// IsMAC returns true if this series originated as a MAC series.  If so, use ToMAC to convert back to the MAC-specific type.
	IsMAC() bool
	// ToIP converts to an IPAddressSegmentSeries if this series originated as IPv4 or IPv6, or an implicitly zero-valued IP.
	// If not, ToIP returns nil.
	ToIP() IPAddressSegmentSeries
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
	// ToMAC converts to a MACAddressSegmentSeries if this series originated as a MAC series.
	// If not, ToMAC returns nil.
	//
	// ToMAC implementations can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
	ToMAC() MACAddressSegmentSeries
	// ToBlock creates a new series block by changing the segment at the given index to have the given lower and upper value,
	// and changing the following segments to be full-range.
	ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries
	// ToPrefixBlock returns the series with the same prefix as this series while the remaining bits span all values.
	// The series will be the block of all series with the same prefix.
	//
	// If this series has no prefix, this series is returned.
	ToPrefixBlock() ExtendedSegmentSeries
	// ToPrefixBlockLen returns the series with the same prefix of the given length as this series while the remaining bits span all values.
	// The returned series will be the block of all series with the same prefix.
	ToPrefixBlockLen(prefLen BitCount) ExtendedSegmentSeries
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
	Increment(int64) ExtendedSegmentSeries
	// IncrementBoundary returns the item that is the given increment from the range boundaries of this item.
	//
	// If the given increment is positive, adds the value to the highest (GetUpper) in the range to produce a new item.
	// If the given increment is negative, adds the value to the lowest (GetLower) in the range to produce a new item.
	// If the increment is zero, returns this.
	//
	// If this represents just a single value, this item is simply incremented by the given increment value, positive or negative.
	//
	// On overflow or underflow, IncrementBoundary returns nil.
	IncrementBoundary(int64) ExtendedSegmentSeries
	// GetLower returns the series in the range with the lowest numeric value,
	// which will be the same series if it represents a single value.
	GetLower() ExtendedSegmentSeries
	// GetUpper returns the series in the range with the highest numeric value,
	// which will be the same series if it represents a single value.
	GetUpper() ExtendedSegmentSeries
	// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this series.
	// The returned block will have an assigned prefix length indicating the prefix length for the block.
	//
	// There may be no such series - it is required that the range of values match the range of a prefix block.
	// If there is no such series, then nil is returned.
	AssignPrefixForSingleBlock() ExtendedSegmentSeries
	// AssignMinPrefixForBlock returns an equivalent series, assigned the smallest prefix length possible,
	// such that the prefix block for that prefix length is in this series.
	//
	// In other words, this method assigns a prefix length to this series matching the largest prefix block in this series.
	AssignMinPrefixForBlock() ExtendedSegmentSeries
	// Iterator provides an iterator to iterate through the individual series of this series.
	//
	// When iterating, the prefix length is preserved.  Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual series.
	//
	// Call IsMultiple to determine if this instance represents multiple series, or GetCount for the count.
	Iterator() Iterator[ExtendedSegmentSeries]
	// PrefixIterator provides an iterator to iterate through the individual prefixes of this series,
	// each iterated element spanning the range of values for its prefix.
	//
	// It is similar to the prefix block iterator, except for possibly the first and last iterated elements, which might not be prefix blocks,
	// instead constraining themselves to values from this series.
	//
	// If the series has no prefix length, then this is equivalent to Iterator.
	PrefixIterator() Iterator[ExtendedSegmentSeries]
	// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks, one for each prefix of this series.
	// Each iterated series will be a prefix block with the same prefix length as this series.
	//
	// If this series has no prefix length, then this is equivalent to Iterator.
	PrefixBlockIterator() Iterator[ExtendedSegmentSeries]
	// AdjustPrefixLen increases or decreases the prefix length by the given increment.
	//
	// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
	//
	// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
	// or it will be set to the adjustment added to the bit count if negative.
	AdjustPrefixLen(BitCount) ExtendedSegmentSeries
	// AdjustPrefixLenZeroed increases or decreases the prefix length by the given increment while zeroing out the bits that have moved into or outside the prefix.
	//
	// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
	//
	// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
	// or it will be set to the adjustment added to the bit count if negative.
	//
	// When prefix length is increased, the bits moved within the prefix become zero.
	// When a prefix length is decreased, the bits moved outside the prefix become zero.
	AdjustPrefixLenZeroed(BitCount) (ExtendedSegmentSeries, address_error.IncompatibleAddressError)
	// SetPrefixLen sets the prefix length.
	//
	// A prefix length will not be set to a value lower than zero or beyond the bit length of the series.
	// The provided prefix length will be adjusted to these boundaries if necessary.
	SetPrefixLen(BitCount) ExtendedSegmentSeries
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
	SetPrefixLenZeroed(BitCount) (ExtendedSegmentSeries, address_error.IncompatibleAddressError)
	// WithoutPrefixLen provides the same address series but with no prefix length.  The values remain unchanged.
	WithoutPrefixLen() ExtendedSegmentSeries
	// ReverseBytes returns a new segment series with the bytes reversed.  Any prefix length is dropped.
	//
	// If each segment is more than 1 byte long, and the bytes within a single segment cannot be reversed because the segment represents a range,
	// and reversing the segment values results in a range that is not contiguous, then this returns an error.
	//
	// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
	ReverseBytes() (ExtendedSegmentSeries, address_error.IncompatibleAddressError)
	// ReverseBits returns a new segment series with the bits reversed.  Any prefix length is dropped.
	//
	// If the bits within a single segment cannot be reversed because the segment represents a range,
	// and reversing the segment values results in a range that is not contiguous, this returns an error.
	//
	// In practice this means that to be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
	ReverseBits(perByte bool) (ExtendedSegmentSeries, address_error.IncompatibleAddressError)
	// ReverseSegments returns a new series with the segments reversed.
	ReverseSegments() ExtendedSegmentSeries
	// ToCustomString creates a customized string from this series according to the given string option parameters.
	ToCustomString(stringOptions address_string.StringOptions) string
}

// WrappedAddress is the implementation of ExtendedSegmentSeries for addresses.
type WrappedAddress struct {
	*Address
}

// GetSection returns the backing section for this series, comprising all segments.
func (addr WrappedAddress) GetSection() *AddressSection {
	return addr.Address.GetSection()
}

// Equal returns whether the given address series is equal to this address series.
// Two address series are equal if they represent the same set of series.
// Both must be equal addresses.
func (addr WrappedAddress) Equal(other ExtendedSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.Address.Equal(a)
}

// Unwrap returns the wrapped address as an interface, AddressSegmentSeries.
func (addr WrappedAddress) Unwrap() AddressSegmentSeries {
	res := addr.Address
	if res == nil {
		return nil
	}
	return res
}

// ToIPv4 converts to an IPv4AddressSegmentSeries if this series originated as an IPv4 series.
// If not, ToIPv4 returns nil.
//
// ToIPv4 implementations can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr WrappedAddress) ToIPv4() IPv4AddressSegmentSeries {
	return addr.Address.ToIPv4()
}

// ToIPv6 converts to an IPv4AddressSegmentSeries if this series originated as an IPv6 series.
// If not, ToIPv6 returns nil.
//
// ToIPv6 implementations can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr WrappedAddress) ToIPv6() IPv6AddressSegmentSeries {
	return addr.Address.ToIPv6()
}

// ToIP converts to an IP address if this originated as IPv4 or IPv6, or an implicitly zero-valued IP.
// If not, ToIP returns nil.
func (addr WrappedAddress) ToIP() IPAddressSegmentSeries {
	return addr.Address.ToIP()
}

// ToMAC converts to a MACAddressSegmentSeries if this series originated as a MAC series.
// If not, ToMAC returns nil.
//
// ToMAC implementations can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (addr WrappedAddress) ToMAC() MACAddressSegmentSeries {
	return addr.Address.ToMAC()
}

// AdjustPrefixLen increases or decreases the prefix length by the given increment.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
//
// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
func (addr WrappedAddress) AdjustPrefixLen(prefixLen BitCount) ExtendedSegmentSeries {
	return wrapAddress(addr.Address.AdjustPrefixLen(prefixLen))
}

// AdjustPrefixLenZeroed increases or decreases the prefix length by the given increment while zeroing out the bits that have moved into or outside the prefix.
//
// A prefix length will not be adjusted lower than zero or beyond the bit length of the series.
//
// If this series has no prefix length, then the prefix length will be set to the adjustment if positive,
// or it will be set to the adjustment added to the bit count if negative.
//
// When prefix length is increased, the bits moved within the prefix become zero.
// When a prefix length is decreased, the bits moved outside the prefix become zero.
func (addr WrappedAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (ExtendedSegmentSeries, address_error.IncompatibleAddressError) {
	return wrapAddrWithErr(addr.Address.AdjustPrefixLenZeroed(prefixLen))
}

// AssignPrefixForSingleBlock returns the equivalent prefix block that matches exactly the range of values in this series.
// The returned block will have an assigned prefix length indicating the prefix length for the block.
//
// There may be no such series - it is required that the range of values match the range of a prefix block.
// If there is no such series, then nil is returned.
func (addr WrappedAddress) AssignPrefixForSingleBlock() ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.AssignPrefixForSingleBlock())
}

// AssignMinPrefixForBlock returns an equivalent series, assigned the smallest prefix length possible,
// such that the prefix block for that prefix length is in this series.
//
// In other words, this method assigns a prefix length to this series matching the largest prefix block in this series.
func (addr WrappedAddress) AssignMinPrefixForBlock() ExtendedSegmentSeries {
	return wrapAddress(addr.Address.AssignMinPrefixForBlock())
}

// Contains returns whether this is same type and version as the given address series and whether it contains all values in the given series.
//
// Series must also have the same number of segments to be comparable, otherwise false is returned.
func (addr WrappedAddress) Contains(other ExtendedSegmentSeries) bool {
	a, ok := other.Unwrap().(AddressType)
	return ok && addr.Address.Contains(a)
}

// Iterator provides an iterator to iterate through the individual series of this series.
//
// When iterating, the prefix length is preserved.
// Remove it using WithoutPrefixLen prior to iterating if you wish to drop it from all individual series.
//
// Call IsMultiple to determine if this instance represents multiple series, or GetCount for the count.
func (addr WrappedAddress) Iterator() Iterator[ExtendedSegmentSeries] {
	return addressSeriesIterator{addr.Address.Iterator()}
}

// PrefixIterator provides an iterator to iterate through the individual prefixes of this series,
// each iterated element spanning the range of values for its prefix.
//
// It is similar to the prefix block iterator,
// except for possibly the first and last iterated elements,
// which might not be prefix blocks,
// instead constraining themselves to values from this series.
//
// If the series has no prefix length, then this is equivalent to Iterator.
func (addr WrappedAddress) PrefixIterator() Iterator[ExtendedSegmentSeries] {
	return addressSeriesIterator{addr.Address.PrefixIterator()}
}

// PrefixBlockIterator provides an iterator to iterate through the individual prefix blocks, one for each prefix of this series.
// Each iterated series will be a prefix block with the same prefix length as this series.
//
// If this series has no prefix length, then this is equivalent to Iterator.
func (addr WrappedAddress) PrefixBlockIterator() Iterator[ExtendedSegmentSeries] {
	return addressSeriesIterator{addr.Address.PrefixBlockIterator()}
}

// ToBlock creates a new series block by changing the segment at the given index to have the given lower and upper value,
// and changing the following segments to be full-range.
func (addr WrappedAddress) ToBlock(segmentIndex int, lower, upper SegInt) ExtendedSegmentSeries {
	return wrapAddress(addr.Address.ToBlock(segmentIndex, lower, upper))
}

// ToPrefixBlock returns the series with the same prefix as this series while the remaining bits span all values.
// The series will be the block of all series with the same prefix.
//
// If this series has no prefix, this series is returned.
func (addr WrappedAddress) ToPrefixBlock() ExtendedSegmentSeries {
	return wrapAddress(addr.Address.ToPrefixBlock())
}

// ToPrefixBlockLen returns the series with the same prefix of the given length as this series while the remaining bits span all values.
// The returned series will be the block of all series with the same prefix.
func (addr WrappedAddress) ToPrefixBlockLen(prefLen BitCount) ExtendedSegmentSeries {
	return wrapAddress(addr.Address.ToPrefixBlockLen(prefLen))
}

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
func (addr WrappedAddress) Increment(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.Increment(i))
}

// IncrementBoundary returns the item that is the given increment from the range boundaries of this item.
//
// If the given increment is positive, adds the value to the highest (GetUpper) in the range to produce a new item.
// If the given increment is negative, adds the value to the lowest (GetLower) in the range to produce a new item.
// If the increment is zero, returns this.
//
// If this represents just a single value, this item is simply incremented by the given increment value, positive or negative.
//
// On overflow or underflow, IncrementBoundary returns nil.
func (addr WrappedAddress) IncrementBoundary(i int64) ExtendedSegmentSeries {
	return convAddrToIntf(addr.Address.IncrementBoundary(i))
}

// GetLower returns the series in the range with the lowest numeric value,
// which will be the same series if it represents a single value.
func (addr WrappedAddress) GetLower() ExtendedSegmentSeries {
	return wrapAddress(addr.Address.GetLower())
}

// GetUpper returns the series in the range with the highest numeric value,
// which will be the same series if it represents a single value.
func (addr WrappedAddress) GetUpper() ExtendedSegmentSeries {
	return wrapAddress(addr.Address.GetUpper())
}

// WrappedAddressSection is the implementation of ExtendedSegmentSeries for address sections.
type WrappedAddressSection struct {
	*AddressSection
}

// GetSection returns the backing section for this series, comprising all segments.
func (section WrappedAddressSection) GetSection() *AddressSection {
	return section.AddressSection
}

// Contains returns whether this is same type and version as the given address series and whether it contains all values in the given series.
//
// Series must also have the same number of segments to be comparable, otherwise false is returned.
func (section WrappedAddressSection) Contains(other ExtendedSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.AddressSection.Contains(s)
}

// Equal returns whether the given address series is equal to this address series.
// Two address series are equal if they represent the same set of series.
// Both must be equal sections.
func (section WrappedAddressSection) Equal(other ExtendedSegmentSeries) bool {
	s, ok := other.Unwrap().(AddressSectionType)
	return ok && section.AddressSection.Equal(s)
}

func wrapAddress(addr *Address) WrappedAddress {
	return WrappedAddress{addr}
}

func wrapSection(section *AddressSection) WrappedAddressSection {
	return WrappedAddressSection{section}
}

func wrapSectWithErr(section *AddressSection, err address_error.IncompatibleAddressError) (ExtendedSegmentSeries, address_error.IncompatibleAddressError) {
	if err == nil {
		return wrapSection(section), nil
	}
	return nil, err
}

func wrapAddrWithErr(addr *Address, err address_error.IncompatibleAddressError) (ExtendedSegmentSeries, address_error.IncompatibleAddressError) {
	if err == nil {
		return wrapAddress(addr), nil
	}
	return nil, err
}

// In go, a nil value is not converted to a nil interface,
// it is converted to a non-nil interface instance with underlying value nil.
func convAddrToIntf(addr *Address) ExtendedSegmentSeries {
	if addr == nil {
		return nil
	}
	return wrapAddress(addr)
}

func convSectToIntf(sect *AddressSection) ExtendedSegmentSeries {
	if sect == nil {
		return nil
	}
	return wrapSection(sect)
}
