package goip

import (
	"math/big"
	"math/bits"

	"github.com/pchchv/goip/address_string"
)

var (
	// Wildcards are different, here we only use the range, since the div size is not implicit.
	octalParamsDiv   = new(address_string.IPStringOptionsBuilder).SetRadix(8).SetSegmentStrPrefix(OctalPrefix).SetWildcards(rangeWildcard).ToOptions()
	hexParamsDiv     = new(address_string.IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).SetWildcards(rangeWildcard).ToOptions()
	decimalParamsDiv = new(address_string.IPStringOptionsBuilder).SetRadix(10).SetWildcards(rangeWildcard).ToOptions()
)

// DivInt is an integer type for holding generic division values,
// which can be larger than segment values.
type DivInt = uint64

type divIntVals interface {
	// getDivisionValue gets the lower value for a division
	getDivisionValue() DivInt
	// getUpperDivisionValue gets the upper value for a division
	getUpperDivisionValue() DivInt
}

type divderiver interface {
	// deriveNew produces a new division with the same bit count as the old,
	// but with the new values and prefix length
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues
	// derivePrefixed produces a new division with the same bit count and values as the old,
	// but with the new prefix length
	derivePrefixed(prefLen PrefixLen) divisionValues
}

type addressDivisionInternal struct {
	addressDivisionBase
}

func (div *addressDivisionInternal) isPrefixed() bool {
	return div.getDivisionPrefixLength() != nil
}

func (div *addressDivisionInternal) getDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getDivisionValue()
}

func (div *addressDivisionInternal) getUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperDivisionValue()
}

func (div *addressDivisionInternal) matches(value DivInt) bool {
	return !div.isMultiple() && value == div.getDivisionValue()
}

func (div *addressDivisionInternal) matchesWithMask(value, mask DivInt) bool {
	if div.isMultiple() {
		// make sure that any of the bits that can change from value to upperValue are masked out (zeroed) by the mask
		// in other words, when masking, it is necessary that all values represented by this segment to become just a single value
		diffBits := div.getDivisionValue() ^ div.getUpperDivisionValue()
		leadingZeros := bits.LeadingZeros64(diffBits)
		// bits that can be changed are all bits following the first leadingZero bits, all subsequent bits must be zeroed by the mask
		fullMask := ^DivInt(0) >> uint(leadingZeros)
		if (fullMask & mask) != 0 {
			return false
		} // else know that the mask zeros out all bits that can change from value to upperValue, so now just compare with either one
	}
	return value == (div.getDivisionValue() & mask)
}

func (div *addressDivisionInternal) matchesIPSegment() bool {
	return div.divisionValues == nil || div.getAddrType().isIP()
}

func (div *addressDivisionInternal) matchesIPv4Segment() bool {
	// init() methods ensure that even segments with zero IPv4 (IPv4Segment{}) have an IPv4 address type
	return div.divisionValues != nil && div.getAddrType().isIPv4()
}

func (div *addressDivisionInternal) matchesIPv6Segment() bool {
	// init() methods ensure that even zero IPv6 segments (IPv6Segment{}) are of IPv6 address type
	return div.divisionValues != nil && div.getAddrType().isIPv6()
}

func (div *addressDivisionInternal) matchesMACSegment() bool {
	// init() methods ensure that even zero MAC segments (MACSegment{}) are of the addr MAC type
	return div.divisionValues != nil && div.getAddrType().isMAC()
}

// getDefaultRangeSeparatorString() is a wildcard string that will be used when producing default strings with getString() or getWildcardString().
// Since no parameters are provided for the string, default settings are used, but they must match the address.
// For example, generally '-' is used as a range separator, but in some cases this character is used to segment separator.
// Note that this only applies to the 'default' settings, there are additional string methods that allow to specify these delimiter characters.
// These methods must be aware of the default settings, to know when they can defer to the defaults and when they cannot.
func (div *addressDivisionInternal) getDefaultRangeSeparatorString() string {
	return "-"
}

// AddressDivision represents an arbitrary division in an address or grouping of address divisions.
// It can contain a single value or a range of sequential values and has an assigned bit length.
// Like all address components, it is immutable.
// Divisions that have been converted from IPv4, IPv6, or MAC segments can be converted back to segments of the same type and version.
// Divisions that have not been converted from IPv4, IPv6 or MAC cannot be converted to segments.
type AddressDivision struct {
	addressDivisionInternal
}

// GetDivisionValue returns the lower division value in the range.
func (div *AddressDivision) GetDivisionValue() DivInt {
	return div.getDivisionValue()
}

// GetUpperDivisionValue returns the upper division value in the range.
func (div *AddressDivision) GetUpperDivisionValue() DivInt {
	return div.getUpperDivisionValue()
}

// IsMultiple returns whether the given division represents a sequential range of values rather than a single value.
func (div *AddressDivision) IsMultiple() bool {
	return div != nil && div.isMultiple()
}

// GetCount returns a count of possible distinct values for this division.
// If no multiple values are represented, the counter is 1.
// For instance, a division with a value range of 3-7 has a count 5.
// Use IsMultiple if you just want to know if the counter is greater than 1.
func (div *AddressDivision) GetCount() *big.Int {
	if div == nil {
		return bigZero()
	}
	return div.getCount()
}

// Matches returns true if the division range matches the given single value.
func (div *AddressDivision) Matches(value DivInt) bool {
	return div.matches(value)
}

// MatchesWithMask applies a mask to a this division and then compares the result to the given value,
// returning true if the range of the resulting division matches that single value.
func (div *AddressDivision) MatchesWithMask(value, mask DivInt) bool {
	return div.matchesWithMask(value, mask)
}

// IsIP returns true if this division occurred as an IPv4 or IPv6 segment, or an implicitly zero-valued IP segment.
// If so, use ToIP to convert back to IP-specific type.
func (div *AddressDivision) IsIP() bool {
	return div != nil && div.matchesIPSegment()
}

// IsIPv4 returns true if this division originated as an IPv4 segment.
// If so, use ToIPv4 to convert back to IPv4-specific type.
func (div *AddressDivision) IsIPv4() bool {
	return div != nil && div.matchesIPv4Segment()
}
