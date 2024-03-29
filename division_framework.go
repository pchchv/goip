package goip

var (
	_             StandardDivisionType = &AddressDivision{}
	_             DivisionType         = &IPAddressLargeDivision{}
	_, _, _, _, _ AddressSegmentType   = &AddressSegment{}, &IPAddressSegment{}, &IPv6AddressSegment{}, &IPv4AddressSegment{}, &MACAddressSegment{}
)

// DivisionType serves as a common interface to all divisions
type DivisionType interface {
	AddressItem
	getAddrType() addrType
	// getStringAsLower caches the string from getDefaultLowerString.
	getStringAsLower() string
	// GetString produces a string that avoids wildcards when a prefix length is part of the string.  Equivalent to GetWildcardString when the prefix length is not part of the string.
	GetString() string
	// GetWildcardString produces a string that uses wildcards and avoids prefix length.
	GetWildcardString() string
	// IsSinglePrefix determines if the division has a single prefix for the given prefix length.  You can call GetPrefixCountLen to get the count of prefixes.
	IsSinglePrefix(BitCount) bool
	// methods for string generation used by the string params and string writer.
	divStringProvider
}

// AddressSegmentType serves as a common interface for all segments,
// including [AddressSegment], [IPAddressSegment], [IPv6AddressSegment], [IPv4AddressSegment] and [MACAddressSegment].
type AddressSegmentType interface {
	AddressComponent
	StandardDivisionType
	// Equal returns whether the given segment is equal to this segment.
	// Two segments are equal if they match:
	// - type/version (IPv4, IPv6, MAC)
	// - range of values
	// Prefix lengths are ignored.
	Equal(AddressSegmentType) bool
	// Contains returns whether this segment is same type and version as the given segment and whether it contains all values in the given segment.
	Contains(AddressSegmentType) bool
	// GetSegmentValue returns the lower value of the segment value range as a SegInt.
	GetSegmentValue() SegInt
	// GetUpperSegmentValue returns the upper value of the segment value range as a SegInt.
	GetUpperSegmentValue() SegInt
	// ToSegmentBase converts to an AddressSegment, a polymorphic type used with all address segments.
	//
	// Implementations of ToSegmentBase can be called with a nil receiver,
	// allowing this method to be used in a chain with methods that can return a nil pointer.
	ToSegmentBase() *AddressSegment
}

// StandardDivisionType represents any standard address division, which is a division of size 64 bits or less.
// All can be converted to/from [AddressDivision].
type StandardDivisionType interface {
	DivisionType
	// ToDiv converts to an AddressDivision, a polymorphic type usable with all address segments and divisions.
	//
	// ToDiv implementations can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
	ToDiv() *AddressDivision
}
