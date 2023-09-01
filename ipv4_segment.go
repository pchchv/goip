package goip

import (
	"math/big"
	"unsafe"
)

const useIPv4SegmentCache = true

var (
	allRangeValsIPv4 = &ipv4SegmentValues{
		upperValue: IPv4MaxValuePerSegment,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
	prefixBlocksCacheIPv4                 = makeDivsBlock()
	segmentPrefixCacheIPv4                = makeDivsBlock()
	zeroIPv4Seg                           = NewIPv4Segment(0)
	allPrefixedCacheIPv4                  = makePrefixCache()
	segmentCacheIPv4                      = makeSegmentCache()
	zeroIPv4SegZeroPrefix                 = NewIPv4PrefixedSegment(0, cacheBitCount(0))
	zeroIPv4SegPrefixBlock                = NewIPv4RangePrefixedSegment(0, IPv4MaxValuePerSegment, cacheBitCount(0))
	_                      divisionValues = &ipv4SegmentValues{}
)

type IPv4SegInt = uint8

type IPv4SegmentValueProvider func(segmentIndex int) IPv4SegInt

type ipv4DivsBlock struct {
	block []ipv4SegmentValues
}

// IPv4AddressSegment represents a segment of an IPv4 address.
// An IPv4 segment contains a single value or a range of sequential values,
// a prefix length, and it has bit length of 8 bits.
//
// Like strings, segments are immutable, which also makes them concurrency-safe.
//
// See AddressSegment for more details regarding segments.
type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv4AddressSegment) init() *IPv4AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv4Seg
	}
	return seg
}

// GetIPv4SegmentValue returns the lower value.
// Same as GetSegmentValue but returned as a IPv4SegInt.
func (seg *IPv4AddressSegment) GetIPv4SegmentValue() IPv4SegInt {
	return IPv4SegInt(seg.GetSegmentValue())
}

// GetIPv4UpperSegmentValue returns the lower value.
// Same as GetUpperSegmentValue but returned as a IPv4SegInt.
func (seg *IPv4AddressSegment) GetIPv4UpperSegmentValue() IPv4SegInt {
	return IPv4SegInt(seg.GetUpperSegmentValue())
}

// Contains returns whether this is same type and version as the given segment and whether it contains all values in the given segment.
func (seg *IPv4AddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToSegmentBase() == nil
	}
	return seg.init().contains(other)
}

// Equal returns whether the given segment is equal to this segment.
// Two segments are equal if they match:
//   - type/version: IPv4
//   - value range
//
// Prefix lengths are ignored.
func (seg *IPv4AddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToDiv() == nil
	}
	return seg.init().equal(other)
}

// PrefixContains returns whether the prefix values in
// the prefix of the given segment are also prefix values in this segment.
// It returns whether the prefix of this segment contains the prefix of the given segment.
func (seg *IPv4AddressSegment) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().ipAddressSegmentInternal.PrefixContains(other, prefixLength)
}

// PrefixEqual returns whether the prefix bits of this segment match the same bits of the given segment.
// It returns whether the two segments share the same range of prefix values using the given prefix length.
func (seg *IPv4AddressSegment) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().ipAddressSegmentInternal.PrefixEqual(other, prefixLength)
}

// GetBitCount returns the number of bits in each value comprising this address item, which is 8.
func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

// GetByteCount returns the number of bytes required for each value comprising this address item, which is 1.
func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

// GetMaxValue gets the maximum possible value for this type or version of segment, determined by the number of bits.
//
// For the highest range value of this particular segment, use GetUpperSegmentValue.
func (seg *IPv4AddressSegment) GetMaxValue() IPv4SegInt {
	return 0xff
}

// IsMultiple returns whether this segment represents multiple values.
func (seg *IPv4AddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

// GetCount returns the count of possible distinct values for this item.
// If not representing multiple values, the count is 1.
//
// For instance, a segment with the value range of 3-7 has count 5.
//
// Use IsMultiple if you simply want to know if the count is greater than 1.
func (seg *IPv4AddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

// GetPrefixCountLen returns the count of the number of distinct prefix values for
// the given prefix length in the range of values of this segment.
func (seg *IPv4AddressSegment) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return seg.init().ipAddressSegmentInternal.GetPrefixCountLen(segmentPrefixLength)
}

// GetPrefixValueCountLen returns the same value as GetPrefixCountLen as an integer.
func (seg *IPv4AddressSegment) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return seg.init().ipAddressSegmentInternal.GetPrefixValueCountLen(segmentPrefixLength)
}

// IsOneBit returns true if the bit in the lower value of this segment at the given index is 1,
// where index 0 is the most significant bit.
func (seg *IPv4AddressSegment) IsOneBit(segmentBitIndex BitCount) bool {
	return seg.init().ipAddressSegmentInternal.IsOneBit(segmentBitIndex)
}

type ipv4SegmentValues struct {
	value      IPv4SegInt
	upperValue IPv4SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv4SegmentValues) getAddrType() addrType {
	return ipv4Type
}

func (seg *ipv4SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv4SegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg *ipv4SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv4SegmentValues) getCount() *big.Int {
	return big.NewInt(int64(seg.upperValue-seg.value) + 1)
}

func (seg *ipv4SegmentValues) getBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *ipv4SegmentValues) getByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *ipv4SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv4SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv4SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv4SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *ipv4SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

func (seg *ipv4SegmentValues) bytesInternal(upper bool) []byte {
	if upper {
		return []byte{byte(seg.upperValue)}
	}
	return []byte{byte(seg.value)}
}

func (seg *ipv4SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg *ipv4SegmentValues) derivePrefixed(prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedValues(seg.value, seg.upperValue, prefLen)
}

func (seg *ipv4SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedVal(IPv4SegInt(val), prefLen)
}

func (seg *ipv4SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func newIPv4Segment(vals *ipv4SegmentValues) *IPv4AddressSegment {
	return &IPv4AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{
						vals,
					},
				},
			},
		},
	}
}

func makePrefixCache() (allPrefixedCacheIPv4 []ipv4SegmentValues) {
	if useIPv4SegmentCache {
		allPrefixedCacheIPv4 = make([]ipv4SegmentValues, IPv4BitsPerSegment+1)
		for i := range allPrefixedCacheIPv4 {
			vals := &allPrefixedCacheIPv4[i]
			vals.upperValue = IPv4MaxValuePerSegment
			vals.prefLen = cacheBitCount(i)
			vals.cache.isSinglePrefBlock = &falseVal
		}
		allPrefixedCacheIPv4[0].cache.isSinglePrefBlock = &trueVal
	}
	return
}

func makeSegmentCache() (segmentCacheIPv4 []ipv4SegmentValues) {
	if useIPv4SegmentCache {
		segmentCacheIPv4 = make([]ipv4SegmentValues, IPv4MaxValuePerSegment+1)
		for i := range segmentCacheIPv4 {
			vals := &segmentCacheIPv4[i]
			segi := IPv4SegInt(i)
			vals.value = segi
			vals.upperValue = segi
			vals.cache.isSinglePrefBlock = &falseVal
		}
	}
	return
}

func makeDivsBlock() []*ipv4DivsBlock {
	if useIPv4SegmentCache {
		return make([]*ipv4DivsBlock, IPv4BitsPerSegment+1)
	}
	return nil
}

func newIPv4SegmentVal(value IPv4SegInt) *ipv4SegmentValues {
	if useIPv4SegmentCache {
		result := &segmentCacheIPv4[value]
		return result
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
}

func newIPv4SegmentPrefixedVal(value IPv4SegInt, prefLen PrefixLen) (result *ipv4SegmentValues) {
	var isSinglePrefBlock *bool

	if prefLen == nil {
		return newIPv4SegmentVal(value)
	}

	segmentPrefixLength := prefLen.bitCount()
	if segmentPrefixLength < 0 {
		segmentPrefixLength = 0
	} else if segmentPrefixLength > IPv4BitsPerSegment {
		segmentPrefixLength = IPv4BitsPerSegment
	}

	prefLen = cacheBitCount(segmentPrefixLength) // this ensures we use the prefix length cache for all segments

	if useIPv4SegmentCache {
		prefixIndex := segmentPrefixLength
		cache := segmentPrefixCacheIPv4
		block := (*ipv4DivsBlock)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))))
		if block == nil {
			block = &ipv4DivsBlock{make([]ipv4SegmentValues, IPv4MaxValuePerSegment+1)}
			vals := block.block
			var isSinglePrefBlock *bool
			if prefixIndex == IPv4BitsPerSegment {
				isSinglePrefBlock = &trueVal
			} else {
				isSinglePrefBlock = &falseVal
			}
			for i := range vals {
				value := &vals[i]
				segi := IPv4SegInt(i)
				value.value = segi
				value.upperValue = segi
				value.prefLen = prefLen
				value.cache.isSinglePrefBlock = isSinglePrefBlock
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
			atomicStorePointer(dataLoc, unsafe.Pointer(block))
		}
		result = &block.block[value]
		return result
	}

	if segmentPrefixLength == IPv4BitsPerSegment {
		isSinglePrefBlock = &trueVal
	} else {
		isSinglePrefBlock = &falseVal
	}

	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

// NewIPv4Segment constructs a segment of an IPv4 address with the given value.
func NewIPv4Segment(val IPv4SegInt) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentVal(val))
}

// NewIPv4PrefixedSegment constructs a segment of an IPv4 address with the given value and assigned prefix length.
func NewIPv4PrefixedSegment(val IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedVal(val, prefixLen))
}

func newIPv4SegmentPrefixedValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
	var isSinglePrefBlock *bool

	if prefLen == nil {
		if value == upperValue {
			return newIPv4SegmentVal(value)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		if useIPv4SegmentCache && value == 0 && upperValue == IPv4MaxValuePerSegment {
			return allRangeValsIPv4
		}
		isSinglePrefBlock = &falseVal
	} else {
		if value == upperValue {
			return newIPv4SegmentPrefixedVal(value, prefLen)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		segmentPrefixLength := prefLen.bitCount()
		if segmentPrefixLength < 0 {
			segmentPrefixLength = 0
		} else if segmentPrefixLength > IPv4BitsPerSegment {
			segmentPrefixLength = IPv4BitsPerSegment
		}
		prefLen = cacheBitCount(segmentPrefixLength) // this ensures we use the prefix length cache for all segments
		if useIPv4SegmentCache {
			// cache is the prefix block for any prefix length
			shiftBits := uint(IPv4BitsPerSegment - segmentPrefixLength)
			nmask := ^IPv4SegInt(0) << shiftBits
			prefixBlockLower := value & nmask
			hmask := ^nmask
			prefixBlockUpper := value | hmask
			if value == prefixBlockLower && upperValue == prefixBlockUpper {
				valueIndex := value >> shiftBits
				cache := prefixBlocksCacheIPv4
				prefixIndex := segmentPrefixLength
				block := (*ipv4DivsBlock)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))))
				var result *ipv4SegmentValues
				if block == nil {
					block = &ipv4DivsBlock{make([]ipv4SegmentValues, 1<<uint(segmentPrefixLength))}
					vals := block.block
					for i := range vals {
						value := &vals[i]
						segi := IPv4SegInt(i << shiftBits)
						value.value = segi
						value.upperValue = segi | hmask
						value.prefLen = prefLen
						value.cache.isSinglePrefBlock = &trueVal
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
					atomicStorePointer(dataLoc, unsafe.Pointer(block))
				}
				result = &block.block[valueIndex]
				return result
			}
			if value == 0 {
				// cache is 0-255 for any prefix length
				if upperValue == IPv4MaxValuePerSegment {
					result := &allPrefixedCacheIPv4[segmentPrefixLength]
					return result
				}
			}
			isSinglePrefBlock = &falseVal
		}
	}

	return &ipv4SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

// NewIPv4RangeSegment constructs a segment of an IPv4 subnet with the given range of sequential values.
func NewIPv4RangeSegment(val, upperVal IPv4SegInt) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedValues(val, upperVal, nil))
}

// NewIPv4RangePrefixedSegment constructs a segment of
// an IPv4 subnet with the given range of sequential values and assigned prefix length.
func NewIPv4RangePrefixedSegment(val, upperVal IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedValues(val, upperVal, prefixLen))
}

// WrapIPv4SegmentValueProvider converts the given IPv4SegmentValueProvider to a SegmentValueProvider.
func WrapIPv4SegmentValueProvider(f IPv4SegmentValueProvider) SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) SegInt {
		return SegInt(f(segmentIndex))
	}
}

// WrapSegmentValueProviderForIPv4 converts the given SegmentValueProvider to an IPv4SegmentValueProvider.
// Values that do not fit IPv4SegInt are truncated.
func WrapSegmentValueProviderForIPv4(f SegmentValueProvider) IPv4SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) IPv4SegInt {
		return IPv4SegInt(f(segmentIndex))
	}
}
