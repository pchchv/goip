package goip

import "math/big"

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
