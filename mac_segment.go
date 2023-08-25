package goip

import "math/big"

const useMACSegmentCache = true

var (
	allRangeValsMAC = &macSegmentValues{
		upperValue: MACMaxValuePerSegment,
	}
	segmentCacheMAC = makeSegmentCacheMAC()
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
