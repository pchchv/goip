package goip

import (
	"math/big"

	"github.com/pchchv/goip/address_error"
)

const useMACSegmentCache = true

var (
	_               divisionValues = &macSegmentValues{}
	segmentCacheMAC                = makeSegmentCacheMAC()
	zeroMACSeg                     = NewMACSegment(0)
	allRangeMACSeg                 = NewMACRangeSegment(0, MACMaxValuePerSegment)
	allRangeValsMAC                = &macSegmentValues{
		upperValue: MACMaxValuePerSegment,
	}
)

type MACSegInt = uint8

type MACSegmentValueProvider func(segmentIndex int) MACSegInt

// MACAddressSegment represents a segment of a MAC address.
// For MAC, segments are 1 byte.
// A MAC segment contains a single value or a range of sequential values,
// a prefix length, and it has bit length of 8 bits.
//
// Segments are immutable, which also makes them concurrency-safe.
type MACAddressSegment struct {
	addressSegmentInternal
}

// GetMACSegmentValue returns the lower value.
// Same as GetSegmentValue but returned as a MACSegInt.
func (seg *MACAddressSegment) GetMACSegmentValue() MACSegInt {
	return MACSegInt(seg.GetSegmentValue())
}

// GetMACUpperSegmentValue returns the lower value.
// Same as GetUpperSegmentValue but returned as a MACSegInt.
func (seg *MACAddressSegment) GetMACUpperSegmentValue() MACSegInt {
	return MACSegInt(seg.GetUpperSegmentValue())
}

func (seg *MACAddressSegment) init() *MACAddressSegment {
	if seg.divisionValues == nil {
		return zeroMACSeg
	}
	return seg
}

// Contains returns whether this is same type and version as the given segment and whether it contains all values in the given segment.
func (seg *MACAddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToSegmentBase() == nil
	}
	return seg.init().contains(other)
}

// Equal returns whether the given segment is equal to this segment.
// Two segments are equal if they match:
//   - type/version: MAC
//   - value range
//
// Prefix lengths are ignored.
func (seg *MACAddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToDiv() == nil
	}
	return seg.init().equal(other)
}

// PrefixContains returns whether the prefix values in the prefix of the given segment are also prefix values in this segment.
// It returns whether the prefix of this segment contains the prefix of the given segment.
func (seg *MACAddressSegment) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().addressSegmentInternal.PrefixContains(other, prefixLength)
}

// PrefixEqual returns whether the prefix bits of this segment match the same bits of the given segment.
// It returns whether the two segments share the same range of prefix values using the given prefix length.
func (seg *MACAddressSegment) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().addressSegmentInternal.PrefixEqual(other, prefixLength)
}

// GetBitCount returns the number of bits in each value comprising this address item, which is 8.
func (seg *MACAddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

// GetByteCount returns the number of bytes required for each value comprising this address item, which is 1.
func (seg *MACAddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

// GetMaxValue gets the maximum possible value for this type or version of segment,
// determined by the number of bits.
//
// For the highest range value of this particular segment, use GetUpperSegmentValue.
func (seg *MACAddressSegment) GetMaxValue() MACSegInt {
	return 0xff
}

// IsMultiple returns whether this segment represents multiple values.
func (seg *MACAddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

// GetCount returns the count of possible distinct values for this item.
// If not representing multiple values, the count is 1.
//
// For instance, a segment with the value range of 3-7 has count 5.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (seg *MACAddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

// Bytes returns the lowest value in the address segment range as a byte slice.
func (seg *MACAddressSegment) Bytes() []byte {
	return seg.init().addressSegmentInternal.Bytes()
}

// UpperBytes returns the highest value in the address segment range as a byte slice.
func (seg *MACAddressSegment) UpperBytes() []byte {
	return seg.init().addressSegmentInternal.UpperBytes()
}

// CopyBytes copies the lowest value in the address segment range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (seg *MACAddressSegment) CopyBytes(bytes []byte) []byte {
	return seg.init().addressSegmentInternal.CopyBytes(bytes)
}

// CopyUpperBytes copies the highest value in the address segment range into a byte slice.
//
// If the value can fit in the given slice,
// the value is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice is created and returned with the value.
func (seg *MACAddressSegment) CopyUpperBytes(bytes []byte) []byte {
	return seg.init().addressSegmentInternal.CopyUpperBytes(bytes)
}

// GetPrefixCountLen returns the count of the number of distinct prefix values for
// the given prefix length in the range of values of this segment.
func (seg *MACAddressSegment) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return seg.init().addressSegmentInternal.GetPrefixCountLen(segmentPrefixLength)
}

// GetPrefixValueCountLen returns the same value as GetPrefixCountLen as an integer.
func (seg *MACAddressSegment) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return seg.init().addressSegmentInternal.GetPrefixValueCountLen(segmentPrefixLength)
}

// IsOneBit returns true if the bit in the lower value of this segment at
// the given index is 1, where index 0 is the most significant bit.
func (seg *MACAddressSegment) IsOneBit(segmentBitIndex BitCount) bool {
	return seg.init().addressSegmentInternal.IsOneBit(segmentBitIndex)
}

func (seg *MACAddressSegment) setString(addressStr string, isStandardString bool, lowerStringStartIndex, lowerStringEndIndex int, originalLowerValue SegInt) {
	if cache := seg.getCache(); cache != nil {
		if isStandardString && originalLowerValue == seg.getSegmentValue() {
			cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:lowerStringEndIndex] })
		}
	}
}

func (seg *MACAddressSegment) setRangeString(addressStr string, isStandardRangeString bool, lowerStringStartIndex, upperStringEndIndex int, rangeLower, rangeUpper SegInt) {
	if cache := seg.getCache(); cache != nil {
		if seg.IsFullRange() {
			cacheStrPtr(&cache.cachedString, &segmentWildcardStr)
		} else if isStandardRangeString && rangeLower == seg.getSegmentValue() && rangeUpper == seg.getUpperSegmentValue() {
			cacheStr(&cache.cachedString, func() string { return addressStr[lowerStringStartIndex:upperStringEndIndex] })
		}
	}
}

// ReverseBits returns a segment with the bits reversed.
//
// If this segment represents a range of values that cannot be reversed, then this returns an error.
//
// To be reversible, a range must include all values except possibly the largest and/or smallest, which reverse to themselves.
// Otherwise the result is not contiguous and thus cannot be represented by a sequential range of values.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
//
// If perByte is true, the bits are reversed within each byte, otherwise all the bits are reversed.
func (seg *MACAddressSegment) ReverseBits(_ bool) (res *MACAddressSegment, err address_error.IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}

	if seg.isMultiple() {
		if isReversible := seg.isReversibleRange(false); isReversible {
			res = seg
			return
		}
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}

	oldVal := MACSegInt(seg.GetSegmentValue())
	val := MACSegInt(reverseUint8(uint8(oldVal)))
	if oldVal == val {
		res = seg
	} else {
		res = NewMACSegment(val)
	}

	return
}

func (seg *MACAddressSegment) joinSegs(macSegment1 *MACAddressSegment, flip bool, prefixLength PrefixLen) (*IPv6AddressSegment, address_error.IncompatibleAddressError) {
	if seg.isMultiple() {
		// if the high segment has a range, the low segment must match the full range,
		// otherwise it is not possible to create an equivalent range when joining
		if !macSegment1.IsFullRange() {
			return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.invalidMACIPv6Range"}}
		}
	}

	lower0 := seg.GetSegmentValue()
	upper0 := seg.GetUpperSegmentValue()

	if flip {
		mask2ndBit := SegInt(0x2)
		if !seg.MatchesWithMask(mask2ndBit&lower0, mask2ndBit) { // ensures that bit remains constant
			return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
		}
		lower0 ^= mask2ndBit
		upper0 ^= mask2ndBit
	}

	return NewIPv6RangePrefixedSegment(
		IPv6SegInt((lower0<<8)|macSegment1.getSegmentValue()),
		IPv6SegInt((upper0<<8)|macSegment1.getUpperSegmentValue()),
		prefixLength), nil
}

// ReverseBytes returns a segment with the bytes reversed, which for a MAC segment is always the original segment.
func (seg *MACAddressSegment) ReverseBytes() (*MACAddressSegment, address_error.IncompatibleAddressError) {
	return seg, nil
}

// Join joins with another MAC segment to produce a IPv6 segment.
func (seg *MACAddressSegment) Join(macSegment1 *MACAddressSegment, prefixLength PrefixLen) (*IPv6AddressSegment, address_error.IncompatibleAddressError) {
	return seg.joinSegs(macSegment1, false, prefixLength)
}

// JoinAndFlip2ndBit joins with another MAC segment to produce a IPv6 segment with the second bit flipped from 1 to 0.
func (seg *MACAddressSegment) JoinAndFlip2ndBit(macSegment1 *MACAddressSegment, prefixLength PrefixLen) (*IPv6AddressSegment, address_error.IncompatibleAddressError) {
	return seg.joinSegs(macSegment1, true, prefixLength)
}

type macSegmentValues struct {
	value      MACSegInt
	upperValue MACSegInt
	cache      divCache
}

func (seg *macSegmentValues) getAddrType() addrType {
	return macType
}

func (seg *macSegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *macSegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg *macSegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *macSegmentValues) getCount() *big.Int {
	return big.NewInt(int64(seg.upperValue-seg.value) + 1)
}

func (seg *macSegmentValues) getBitCount() BitCount {
	return MACBitsPerSegment
}

func (seg *macSegmentValues) getByteCount() int {
	return MACBytesPerSegment
}

func (seg *macSegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *macSegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *macSegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *macSegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *macSegmentValues) getDivisionPrefixLength() PrefixLen {
	return nil
}

func (seg *macSegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *macSegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *macSegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *macSegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}

	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}

	return
}

func (seg *macSegmentValues) bytesInternal(upper bool) []byte {
	if upper {
		return []byte{byte(seg.upperValue)}
	}
	return []byte{byte(seg.value)}
}

func (seg *macSegmentValues) deriveNew(val, upperVal DivInt, _ PrefixLen) divisionValues {
	return newMACSegmentValues(MACSegInt(val), MACSegInt(upperVal))
}

func (seg *macSegmentValues) deriveNewMultiSeg(val, upperVal SegInt, _ PrefixLen) divisionValues {
	return newMACSegmentValues(MACSegInt(val), MACSegInt(upperVal))
}

func (seg *macSegmentValues) deriveNewSeg(val SegInt, _ PrefixLen) divisionValues {
	return newMACSegmentVal(MACSegInt(val))
}

func (seg *macSegmentValues) derivePrefixed(_ PrefixLen) divisionValues {
	return seg
}

func makeSegmentCacheMAC() (segmentCacheMAC []macSegmentValues) {
	if useMACSegmentCache {
		segmentCacheMAC = make([]macSegmentValues, MACMaxValuePerSegment+1)
		for i := range segmentCacheMAC {
			vals := &segmentCacheMAC[i]
			segi := MACSegInt(i)
			vals.value = segi
			vals.upperValue = segi
		}
	}
	return
}

func newMACSegmentVal(value MACSegInt) *macSegmentValues {
	if useMACSegmentCache {
		result := &segmentCacheMAC[value]
		//checkValuesMAC(value, value, result)
		return result
	}
	return &macSegmentValues{value: value, upperValue: value}
}

func newMACSegmentValues(value, upperValue MACSegInt) *macSegmentValues {
	if value == upperValue {
		return newMACSegmentVal(value)
	} else if value > upperValue {
		value, upperValue = upperValue, value
	}

	if useMACSegmentCache && value == 0 && upperValue == MACMaxValuePerSegment {
		return allRangeValsMAC
	}

	return &macSegmentValues{value: value, upperValue: upperValue}
}

func newMACSegment(vals *macSegmentValues) *MACAddressSegment {
	return &MACAddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{
				addressDivisionBase{vals},
			},
		},
	}
}

// NewMACSegment constructs a segment of a MAC address with the given value.
func NewMACSegment(val MACSegInt) *MACAddressSegment {
	return newMACSegment(newMACSegmentVal(val))
}

// NewMACRangeSegment constructs a segment of a MAC address collection with the given range of sequential values.
func NewMACRangeSegment(val, upperVal MACSegInt) *MACAddressSegment {
	return newMACSegment(newMACSegmentValues(val, upperVal))
}

// WrapMACSegmentValueProvider converts the given MACSegmentValueProvider to a SegmentValueProvider
func WrapMACSegmentValueProvider(f MACSegmentValueProvider) SegmentValueProvider {
	if f != nil {
	return func(segmentIndex int) SegInt {
		return SegInt(f(segmentIndex))
	}
}
	return nil
}

// WrapSegmentValueProviderForMAC converts the given SegmentValueProvider to a MACSegmentValueProvider
// Values that do not fit MACSegInt are truncated.
func WrapSegmentValueProviderForMAC(f SegmentValueProvider) MACSegmentValueProvider {
	if f != nil {
		return func(segmentIndex int) MACSegInt {
			return MACSegInt(f(segmentIndex))
		}
	}
	return nil
}
