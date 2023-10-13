package goip

import (
	"math/big"
	"math/bits"
	"strings"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string"
)

const DivIntSize = 64

var (
	// Wildcards are different, here we only use the range, since the div size is not implicit.
	octalParamsDiv                  = new(address_string.IPStringOptionsBuilder).SetRadix(8).SetSegmentStrPrefix(OctalPrefix).SetWildcards(rangeWildcard).ToOptions()
	hexParamsDiv                    = new(address_string.IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).SetWildcards(rangeWildcard).ToOptions()
	decimalParamsDiv                = new(address_string.IPStringOptionsBuilder).SetRadix(10).SetWildcards(rangeWildcard).ToOptions()
	_                divisionValues = &divIntValues{}
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

func (div *addressDivisionInternal) toAddressDivision() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(div))
}

// GetBitCount returns the number of bits in each value comprising this address item.
func (div *addressDivisionInternal) GetBitCount() BitCount {
	return div.addressDivisionBase.GetBitCount()
}

// isPrefixBlockVals returns whether the division range includes the block of values for its prefix length.
func (div *addressDivisionInternal) isPrefixBlockVals(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	return isPrefixBlockVals(divisionValue, upperValue, divisionPrefixLen, div.GetBitCount())
}

// ContainsPrefixBlock returns whether the division range includes the block of values for the given prefix length.
func (div *addressDivisionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return div.isPrefixBlockVals(div.getDivisionValue(), div.getUpperDivisionValue(), prefixLen)
}

func (div *addressDivisionInternal) toNetworkDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	vals := div.divisionValues
	if vals == nil {
		return div.toAddressDivision()
	}

	var newLower, newUpper DivInt
	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
	hasPrefLen := divPrefixLength != nil
	if hasPrefLen {
		prefBits := divPrefixLength.bitCount()
		bitCount := div.GetBitCount()
		prefBits = checkBitCount(prefBits, bitCount)
		mask := ^DivInt(0) << uint(bitCount-prefBits)
		newLower = lower & mask
		newUpper = upper | ^mask
		if !withPrefixLength {
			divPrefixLength = nil
		}
		if divsSame(divPrefixLength, div.getDivisionPrefixLength(), newLower, lower, newUpper, upper) {
			return div.toAddressDivision()
		}
	} else {
		divPrefixLength = nil
		if div.getDivisionPrefixLength() == nil {
			return div.toAddressDivision()
		}
	}

	newVals := div.deriveNew(newLower, newUpper, divPrefixLength)

	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) toPrefixedNetworkDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toNetworkDivision(divPrefixLength, true)
}

// containsPrefixBlock returns whether the division range includes a value block for a given prefix length.
func (div *addressDivisionInternal) containsPrefixBlock(divisionPrefixLen BitCount) bool {
	return div.isPrefixBlockVals(div.getDivisionValue(), div.getUpperDivisionValue(), divisionPrefixLen)
}

// isPrefixBlock returns whether the division range includes a value block for the prefix length of the division,
// or false if the division has no prefix length.
func (div *addressDivisionInternal) isPrefixBlock() bool {
	prefLen := div.getDivisionPrefixLength()
	return prefLen != nil && div.containsPrefixBlock(prefLen.bitCount())
}

func (div *addressDivisionInternal) toHostDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	var mask SegInt
	vals := div.divisionValues
	if vals == nil {
		return div.toAddressDivision()
	}

	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
	hasPrefLen := divPrefixLength != nil
	if hasPrefLen {
		prefBits := divPrefixLength.bitCount()
		bitCount := div.GetBitCount()
		prefBits = checkBitCount(prefBits, bitCount)
		mask = ^(^SegInt(0) << uint(bitCount-prefBits))
	}

	divMask := uint64(mask)
	maxVal := uint64(^SegInt(0))
	masker := MaskRange(lower, upper, divMask, maxVal)
	newLower, newUpper := masker.GetMaskedLower(lower, divMask), masker.GetMaskedUpper(upper, divMask)

	if !withPrefixLength {
		divPrefixLength = nil
	}

	if divsSame(divPrefixLength, div.getDivisionPrefixLength(), newLower, lower, newUpper, upper) {
		return div.toAddressDivision()
	}

	newVals := div.deriveNew(newLower, newUpper, divPrefixLength)

	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) toPrefixedHostDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toHostDivision(divPrefixLength, true)
}

// getDefaultTextualRadix returns the default radix for text address representations (10 for IPv4, 16 for IPv6, MAC and others)
func (div *addressDivisionInternal) getDefaultTextualRadix() int {
	addrType := div.getAddrType()
	if addrType.isIPv4() {
		return IPv4DefaultTextualRadix
	}
	return 16
}

func (div *addressDivisionInternal) getMaxValue() DivInt {
	return ^(^DivInt(0) << uint(div.GetBitCount()))
}

func (div *addressDivisionInternal) getMaxDigitCountRadix(radix int) int {
	return getMaxDigitCount(radix, div.GetBitCount(), div.getMaxValue())
}

// getMaxDigitCount returns the number of digits for the maximum possible value of the division when using the default radix
func (div *addressDivisionInternal) getMaxDigitCount() int {
	return div.getMaxDigitCountRadix(div.getDefaultTextualRadix())
}

// isSinglePrefix returns whether the given range from divisionValue to upperValue is equivalent to the segmentValue range with the divisionPrefixLen prefix.
func (div *addressDivisionInternal) isSinglePrefix(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	bitCount := div.GetBitCount()
	divisionPrefixLen = checkBitCount(divisionPrefixLen, bitCount)
	shift := uint(bitCount - divisionPrefixLen)
	return (divisionValue >> shift) == (upperValue >> shift)
}

// IsSinglePrefix returns true if the division value range covers only single prefix value for a given prefix length.
func (div *addressDivisionInternal) IsSinglePrefix(divisionPrefixLength BitCount) bool {
	return div.isSinglePrefix(div.getDivisionValue(), div.getUpperDivisionValue(), divisionPrefixLength)
}

func (div *addressDivisionInternal) adjustLeadingZeroCount(leadingZeroCount int, value DivInt, radix int) int {
	if leadingZeroCount < 0 {
		width := getDigitCount(value, radix)
		num := div.getMaxDigitCountRadix(radix) - width
		if num < 0 {
			return 0
		}
		return num
	}
	return leadingZeroCount
}

// If leadingZeroCount is -1, returns the number of leading zeros for the maximum width, based on the width of the value.
func (div *addressDivisionInternal) adjustLowerLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getDivisionValue(), radix)
}

// If leadingZeroCount is -1, returns the number of leading zeros for the maximum width, based on the width of the value.
func (div *addressDivisionInternal) adjustUpperLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getUpperDivisionValue(), radix)
}

// isSinglePrefixBlock returns whether the given range from divisionValue to upperValue is equivalent to the segmentValue range with the divisionPrefixLen prefix.
func (div *addressDivisionInternal) isSinglePrefixBlock(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen == 0 {
		return divisionValue == 0 && upperValue == div.getMaxValue()
	}

	bitCount := div.GetBitCount()
	ones := ^DivInt(0)
	divisionBitMask := ^(ones << uint(bitCount))
	divisionPrefixMask := ones << uint(bitCount-divisionPrefixLen)
	divisionHostMask := ^divisionPrefixMask

	return testRange(divisionValue, divisionValue, upperValue, divisionPrefixMask&divisionBitMask, divisionHostMask)
}

// matchesWithMask returns whether masking with a given mask results in a valid contiguous range for the given segment,
// and if so, whether the result matches the range from lowerValue to upperValue.
func (div *addressDivisionInternal) matchesValsWithMask(lowerValue, upperValue, mask DivInt) bool {
	if lowerValue == upperValue {
		return div.matchesWithMask(lowerValue, mask)
	}

	if !div.isMultiple() {
		// the values to match, lowerValue and upperValue, do not match, so you cannot match these two values with the same value from this segment
		return false
	}

	thisValue := div.getDivisionValue()
	thisUpperValue := div.getUpperDivisionValue()
	masker := MaskRange(thisValue, thisUpperValue, mask, div.getMaxValue())
	if !masker.IsSequential() {
		return false
	}

	return lowerValue == masker.GetMaskedLower(thisValue, mask) && upperValue == masker.GetMaskedUpper(thisUpperValue, mask)
}

func (div *addressDivisionInternal) toPrefixedDivision(divPrefixLength PrefixLen) *AddressDivision {
	hasPrefLen := divPrefixLength != nil
	bitCount := div.GetBitCount()

	if hasPrefLen {
		prefBits := divPrefixLength.bitCount()
		prefBits = checkBitCount(prefBits, bitCount)
		if div.isPrefixed() && prefBits == div.getDivisionPrefixLength().bitCount() {
			return div.toAddressDivision()
		}
	} else {
		return div.toAddressDivision()
	}

	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
	newVals := div.deriveNew(lower, upper, divPrefixLength)
	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) getCount() *big.Int {
	if !div.isMultiple() {
		return bigOne()
	}

	if div.IsFullRange() {
		res := bigZero()
		return res.SetUint64(0xffffffffffffffff).Add(res, bigOneConst())
	}

	return bigZero().SetUint64((div.getUpperDivisionValue() - div.getDivisionValue()) + 1)
}

// GetPrefixCountLen returns the number of distinct prefixes in the division value range for a given prefix length.
func (div *addressDivisionInternal) GetPrefixCountLen(divisionPrefixLength BitCount) *big.Int {
	if div.IsFullRange() {
		return bigZero().Add(bigOneConst(), bigZero().SetUint64(div.getMaxValue()))
	}

	bitCount := div.GetBitCount()
	divisionPrefixLength = checkBitCount(divisionPrefixLength, bitCount)
	shiftAdjustment := bitCount - divisionPrefixLength
	count := ((div.getUpperDivisionValue() >> uint(shiftAdjustment)) - (div.getDivisionValue() >> uint(shiftAdjustment))) + 1
	return bigZero().SetUint64(count)
}

func (div *addressDivisionInternal) matchesSegment() bool {
	return div.GetBitCount() <= SegIntSize
}

// A simple string using just the lower value and the default radix.
func (div *addressDivisionInternal) getDefaultLowerString() string {
	return toDefaultString(div.getDivisionValue(), div.getDefaultTextualRadix())
}

func (div *addressDivisionInternal) getStringFromStringer(stringer func() string) string {
	if div.divisionValues != nil {
		if cache := div.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}
	return stringer()
}

// A simple string using just the lower and upper values and the default radix, separated by the default range character.
func (div *addressDivisionInternal) getDefaultRangeString() string {
	return div.getDefaultRangeStringVals(div.getDivisionValue(), div.getUpperDivisionValue(), div.getDefaultTextualRadix())
}

func (div *addressDivisionInternal) getDivString() string {
	if !div.isMultiple() {
		return div.getStringFromStringer(div.getDefaultLowerString)
	} else {
		return div.getStringFromStringer(div.getDefaultRangeString)
	}
}

func (div *addressDivisionInternal) getWildcardString() string {
	if seg := div.toAddressDivision().ToIP(); seg != nil {
		return seg.GetWildcardString()
	}
	return div.getDivString() // same string as GetString() when not an IP segment
}

func (div *addressDivisionInternal) getLowerString(radix int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getDivisionValue(), radix, 0, uppercase, appendable)
}

func (div *addressDivisionInternal) getLowerStringLength(radix int) int {
	return toUnsignedStringLength(div.getDivisionValue(), radix)
}

func (div *addressDivisionInternal) getLowerStringChopped(radix int, choppedDigits int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getDivisionValue(), radix, choppedDigits, uppercase, appendable)
}

// GetMinPrefixLenForBlock returns the smallest prefix length such that this division includes the block of all values for that prefix length.
//
// If the entire range can be described this way, then this method returns the same value as GetPrefixLenForSingleBlock.
//
// There may be a single prefix, or multiple possible prefix values in this item for the returned prefix length.
// Use GetPrefixLenForSingleBlock to avoid the case of multiple prefix values.
//
// If this division represents a single value, this returns the bit count.
func (div *addressDivisionInternal) GetMinPrefixLenForBlock() BitCount {
	return getMinPrefixLenForBlock(div.getDivisionValue(), div.getUpperDivisionValue(), div.GetBitCount())
}

func (div *addressDivisionInternal) getUpperString(radix int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getUpperDivisionValue(), radix, 0, uppercase, appendable)
}

func (div *addressDivisionInternal) getUpperStringLength(radix int) int {
	return toUnsignedStringLength(div.getUpperDivisionValue(), radix)
}

func (div *addressDivisionInternal) toAddressSegment() *AddressSegment {
	if div.matchesSegment() {
		return (*AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *addressDivisionInternal) getStringAsLower() string {
	if seg := div.toAddressDivision().ToIP(); seg != nil {
		return seg.getStringAsLower()
	}
	return div.getStringFromStringer(div.getDefaultLowerString)
}

func (div *addressDivisionInternal) getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder) {
	if seg := div.toAddressDivision().ToIP(); seg != nil {
		seg.getUpperStringMasked(radix, uppercase, appendable)
	} else if div.isPrefixed() {
		upperValue := div.getUpperDivisionValue()
		mask := ^DivInt(0) << uint(div.GetBitCount()-div.getDivisionPrefixLength().bitCount())
		upperValue &= mask
		toUnsignedStringCased(upperValue, radix, 0, uppercase, appendable)
	} else {
		div.getUpperString(radix, uppercase, appendable)
	}
}

func (div *addressDivisionInternal) getSplitLowerString(radix int, choppedDigits int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) {
	toSplitUnsignedString(div.getDivisionValue(), radix, choppedDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
}

func (div *addressDivisionInternal) getSplitRangeString(rangeSeparator string, wildcard string, radix int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) address_error.IncompatibleAddressError {
	return toUnsignedSplitRangeString(
		div.getDivisionValue(),
		div.getUpperDivisionValue(),
		rangeSeparator,
		wildcard,
		radix,
		uppercase,
		splitDigitSeparator,
		reverseSplitDigits,
		stringPrefix,
		appendable)
}

func (div *addressDivisionInternal) getSplitRangeStringLength(rangeSeparator string, wildcard string, leadingZeroCount int, radix int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string) int {
	return toUnsignedSplitRangeStringLength(
		div.getDivisionValue(),
		div.getUpperDivisionValue(),
		rangeSeparator,
		wildcard,
		leadingZeroCount,
		radix,
		uppercase,
		splitDigitSeparator,
		reverseSplitDigits,
		stringPrefix)
}

func (div *addressDivisionInternal) getDigitCount(radix int) int {
	// optimization - just get the string, which is cached, which speeds up further calls to this or getString()
	if !div.isMultiple() && radix == div.getDefaultTextualRadix() {
		return len(div.getWildcardString())
	}
	return getDigitCount(div.getUpperDivisionValue(), radix)
}

// getDefaultSegmentWildcardString() is the wildcard string to be used when producing
// the default strings with getString() or getWildcardString()
//
// Since no parameters for the string are provided,
// default settings are used, but they must be consistent with the address.
//
// For instance, generally the '*' is used as a wildcard to denote all possible values for a given segment,
// but in some cases that character is used for a segment separator.
//
// Note that this only applies to "default" settings,
// there are additional string methods that allow you to specify these separator characters.
// Those methods must be aware of the defaults as well,
// to know when they can defer to the defaults and when they cannot.
func (div *addressDivisionInternal) getDefaultSegmentWildcardString() string {
	if seg := div.toAddressDivision().ToSegmentBase(); seg != nil {
		return seg.getDefaultSegmentWildcardString()
	}
	return "" // for divisions, the width is variable and max values can change, so using wildcards make no sense
}

// GetByteCount returns the number of bytes required for each value comprising this address item,
// rounding up if the bit count is not a multiple of 8.
func (div *addressDivisionInternal) GetByteCount() int {
	return div.addressDivisionBase.GetByteCount()
}

// GetValue returns the lowest value in the address division range as a big integer.
func (div *addressDivisionInternal) GetValue() *BigDivInt {
	return div.addressDivisionBase.GetValue()
}

// GetUpperValue returns the highest value in the address division range as a big integer.
func (div *addressDivisionInternal) GetUpperValue() *BigDivInt {
	return div.addressDivisionBase.GetUpperValue()
}

// Bytes returns the lowest value in the address division range as a byte slice.
func (div *addressDivisionInternal) Bytes() []byte {
	return div.addressDivisionBase.Bytes()
}

// UpperBytes returns the highest value in the address division range as a byte slice.
func (div *addressDivisionInternal) UpperBytes() []byte {
	return div.addressDivisionBase.UpperBytes()
}

// CopyBytes copies the lowest value in the address division range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (div *addressDivisionInternal) CopyBytes(bytes []byte) []byte {
	return div.addressDivisionBase.CopyBytes(bytes)
}

// CopyUpperBytes copies the highest value in the address division range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (div *addressDivisionInternal) CopyUpperBytes(bytes []byte) []byte {
	return div.addressDivisionBase.CopyUpperBytes(bytes)
}

// IsZero returns whether this division matches exactly the value of zero.
func (div *addressDivisionInternal) IsZero() bool {
	return div.addressDivisionBase.IsZero()
}

// IncludesZero returns whether this item includes the value of zero within its range.
func (div *addressDivisionInternal) IncludesZero() bool {
	return div.addressDivisionBase.IncludesZero()
}

// IsMax returns whether this division matches exactly the maximum possible value, the value whose bits are all ones.
func (div *addressDivisionInternal) IsMax() bool {
	return div.addressDivisionBase.IsMax()
}

// IncludesMax returns whether this division includes the max value, the value whose bits are all ones, within its range.
func (div *addressDivisionInternal) IncludesMax() bool {
	return div.addressDivisionBase.IncludesMax()
}

// IsFullRange returns whether the division range includes all possible values for its bit length.
//
// This is true if and only if both IncludesZero and IncludesMax return true.
func (div *addressDivisionInternal) IsFullRange() bool {
	return div.addressDivisionBase.IsFullRange()
}

// divIntValues are used by AddressDivision.
type divIntValues struct {
	bitCount   BitCount
	value      DivInt
	upperValue DivInt
	prefLen    PrefixLen
	cache      divCache
}

func (div *divIntValues) getBitCount() BitCount {
	return div.bitCount
}

func (div *divIntValues) getByteCount() int {
	return (int(div.getBitCount()) + 7) >> 3
}

func (div *divIntValues) getDivisionPrefixLength() PrefixLen {
	return div.prefLen
}

func (div *divIntValues) getValue() *BigDivInt {
	return big.NewInt(int64(div.value))
}

func (div *divIntValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(div.upperValue))
}

func (div *divIntValues) includesZero() bool {
	return div.value == 0
}

func (div *divIntValues) includesMax() bool {
	return div.upperValue == ^((^DivInt(0)) << uint(div.getBitCount()))
}

func (div *divIntValues) isMultiple() bool {
	return div.value != div.upperValue
}

func (div *divIntValues) getCount() *big.Int {
	res := new(big.Int)
	return res.SetUint64(uint64(div.upperValue-div.value)).Add(res, bigOneConst())
}

func (div *divIntValues) getCache() *divCache {
	return &div.cache
}

func (div *divIntValues) getAddrType() addrType {
	return zeroType
}

func (div *divIntValues) getDivisionValue() DivInt {
	return div.value
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

// IsIPv6 returns true if this division occurred as an IPv6 segment.
// If so, use ToIPv6 to convert back to IPv6-specific type.
func (div *AddressDivision) IsIPv6() bool {
	return div != nil && div.matchesIPv6Segment()
}

// IsMAC returns true if this division originated as a MAC segment.
// If so, use ToMAC to convert back to the MAC-specific type.
func (div *AddressDivision) IsMAC() bool {
	return div != nil && div.matchesMACSegment()
}

// IsSegmentBase returns true if this division originated as an address segment,
// and this can be converted back with ToSegmentBase.
func (div *AddressDivision) IsSegmentBase() bool {
	return div != nil && div.matchesSegment()
}

// ToDiv is an identity method.
// ToDiv can be called with a nil receiver, which allows this method to be
// used in a chain with methods that can return a nil pointer.
func (div *AddressDivision) ToDiv() *AddressDivision {
	return div
}

// ToSegmentBase converts to an AddressSegment if this division originated as a segment.
// If not, ToSegmentBase returns nil.
//
// ToSegmentBase can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (div *AddressDivision) ToSegmentBase() *AddressSegment {
	if div.IsSegmentBase() {
		return (*AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

// ToIPv4 converts to an IPv4AddressSegment if this division originated as an IPv4 segment.
// If not, ToIPv4 returns nil.
//
// ToIPv4 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (div *AddressDivision) ToIPv4() *IPv4AddressSegment {
	if div.IsIPv4() {
		return (*IPv4AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

// ToIPv6 converts to an IPv6AddressSegment if this division originated as an IPv6 segment.
// If not, ToIPv6 returns nil.
//
// ToIPv6 can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (div *AddressDivision) ToIPv6() *IPv6AddressSegment {
	if div.IsIPv6() {
		return (*IPv6AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

// ToIP converts to an IPAddressSegment if this division originated as an IPv4 or IPv6 segment, or an implicitly zero-valued IP segment.
// If not, ToIP returns nil.
//
// ToIP can be called with a nil receiver, enabling you to chain this method with methods that might return a nil pointer.
func (div *AddressDivision) ToIP() *IPAddressSegment {
	if div.IsIP() {
		return (*IPAddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

// GetWildcardString produces a normalized string to represent the segment, favouring wildcards and range characters regardless of any network prefix length.
// The explicit range of a range-valued segment will be printed.
//
// The string returned is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and the bit-length can be deduced from the context.
// The String method produces strings more appropriate when no context is provided.
func (div *AddressDivision) GetWildcardString() string {
	if div == nil {
		return nilString()
	}
	return div.getWildcardString()
}

// CompareSize compares the counts of two items, the number of individual values within.
//
// Rather than calculating counts with GetCount, there can be more efficient ways of determining whether one represents more individual values than another.
//
// CompareSize returns a positive integer if this division has a larger count than the one given, zero if they are the same, or a negative integer if the other has a larger count.
func (div *AddressDivision) CompareSize(other AddressItem) int {
	if div == nil {
		if isNilItem(other) {
			return 0
		}
		// we have size 0, other has size >= 1
		return -1
	}
	return div.compareSize(other)
}

// GetMaxValue gets the maximum possible value for this type of division, determined by the number of bits.
//
// For the highest range value of this particular segment, use GetUpperDivisionValue.
func (div *AddressDivision) GetMaxValue() DivInt {
	return div.getMaxValue()
}

// ToMAC converts to a MACAddressSegment if this division originated as a MAC segment.
// If not, ToMAC returns nil.
//
// ToMAC can be called with a nil receiver,
// enabling you to chain this method with methods that might return a nil pointer.
func (div *AddressDivision) ToMAC() *MACAddressSegment {
	if div.IsMAC() {
		return (*MACAddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

// GetString produces a normalized string to represent the segment.
// If the segment is an IP segment string with CIDR network prefix block for its prefix length,
// then the string contains only the lower value of the block range.
// Otherwise, the explicit range will be printed.
// If the segment is not an IP segment, then the string is the same as that produced by GetWildcardString.
//
// The string returned is useful in the context of creating strings for address sections or full addresses,
// in which case the radix and bit-length can be deduced from the context.
// The String method produces strings more appropriate when no context is provided.
func (div *AddressDivision) GetString() string {
	if div == nil {
		return nilString()
	}
	return div.getString()
}

// MatchesValsWithMask applies the mask to this division and then compares the result with the given values,
// returning true if the range of the resulting division matches the given range.
func (div *AddressDivision) MatchesValsWithMask(lowerValue, upperValue, mask DivInt) bool {
	return div.matchesValsWithMask(lowerValue, upperValue, mask)
}

func testRange(lowerValue, upperValue, finalUpperValue, networkMask, hostMask DivInt) bool {
	return lowerValue == (lowerValue&networkMask) && finalUpperValue == (upperValue|hostMask)
}

func isPrefixBlockVals(divisionValue, upperValue DivInt, divisionPrefixLen, divisionBitCount BitCount) bool {
	if divisionPrefixLen <= 0 {
		if divisionValue != 0 {
			return false
		}
		maxValue := ^(^DivInt(0) << uint(divisionBitCount))
		return upperValue == maxValue
	}
	if divisionPrefixLen >= divisionBitCount {
		return true
	}
	var ones = ^DivInt(0)
	divisionBitMask := ^(ones << uint(divisionBitCount))
	divisionPrefixMask := ones << uint(divisionBitCount-divisionPrefixLen)
	var divisionNonPrefixMask = ^divisionPrefixMask
	return testRange(divisionValue,
		upperValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

func divsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal DivInt) bool {
	return onePref.Equal(twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}

func divValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal DivInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func divValSame(oneVal, twoVal DivInt) bool {
	return oneVal == twoVal
}

func createAddressDivision(vals divisionValues) *AddressDivision {
	return &AddressDivision{
		addressDivisionInternal{
			addressDivisionBase: addressDivisionBase{vals},
		},
	}
}

func cacheStrPtr(cachedString **string, strPtr *string) {
	cachedVal := (*string)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(cachedString))))
	if cachedVal == nil {
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
		atomicStorePointer(dataLoc, unsafe.Pointer(strPtr))
	}
	return
}

func cacheStr(cachedString **string, stringer func() string) (str string) {
	cachedVal := (*string)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(cachedString))))
	if cachedVal == nil {
		str = stringer()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
		atomicStorePointer(dataLoc, unsafe.Pointer(&str))
	} else {
		str = *cachedVal
	}
	return
}

func cacheStrErr(cachedString **string, stringer func() (string, address_error.IncompatibleAddressError)) (str string, err address_error.IncompatibleAddressError) {
	cachedVal := (*string)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(cachedString))))
	if cachedVal == nil {
		str, err = stringer()
		if err == nil {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
			atomicStorePointer(dataLoc, unsafe.Pointer(&str))
		}
	} else {
		str = *cachedVal
	}
	return
}

func calcBytesInternal(byteCount int, val, upperVal DivInt) (bytes, upperBytes []byte) {
	byteIndex := byteCount - 1
	isMultiple := val != upperVal
	bytes = make([]byte, byteCount)
	if isMultiple {
		upperBytes = make([]byte, byteCount)
	} else {
		upperBytes = bytes
	}

	for {
		bytes[byteIndex] |= byte(val)
		val >>= 8
		if isMultiple {
			upperBytes[byteIndex] |= byte(upperVal)
			upperVal >>= 8
		}
		if byteIndex == 0 {
			return bytes, upperBytes
		}
		byteIndex--
	}
}

func calcSingleBytes(byteCount int, val DivInt) (bytes []byte) {
	byteIndex := byteCount - 1
	bytes = make([]byte, byteCount)

	for {
		bytes[byteIndex] |= byte(val)
		val >>= 8
		if byteIndex == 0 {
			return bytes
		}
		byteIndex--
	}
}
