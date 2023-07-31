package goip

import (
	"math/big"
	"unsafe"
)

const useIPv6SegmentCache = true

var (
	// Prefix block cache: all prefix blocks for each prefix.
	// For a given prefix, shift left 8 bits for blocks of size 0x100,
	// the remaining bits on the left are the number of blocks.
	//
	// For a prefix of size 8, 1 block of size 0x100.
	// For a prefix of size < 8, 1 block of size (1 << prefix).
	// For prefix size > 8, (1 << (prefix - 8)) blocks of size 0x100.
	//
	// So, to get the desired ipv6DivsPartition, we need to start with the prefix.
	// Then we use the above formula to find the block index.
	// For the first two cases, the entire prefix finds the index of one block.
	// In the third case, the 8 rightmost bits of the prefix give the index of a block of size ff,
	// and the leftmost bits of the prefix select that block.
	prefixBlocksCacheIPv6  = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1)
	segmentCacheIPv6       = make([]*ipv6DivsBlock, (IPv6MaxValuePerSegment>>8)+1) // single-valued no-prefix cache.
	segmentPrefixCacheIPv6 = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1)      // single-valued cache for each prefix
	allPrefixedCacheIPv6   = makePrefixCacheIPv6()
	allRangeValsIPv6       = &ipv6SegmentValues{
		upperValue: IPv6MaxValuePerSegment,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
	_ divisionValues = &ipv6SegmentValues{}
)

type IPv6SegInt = uint16

type IPv6SegmentValueProvider func(segmentIndex int) IPv6SegInt

type ipv6DivsBlock struct {
	block []ipv6SegmentValues
}

type ipv6DivsPartition struct {
	block []*ipv6DivsBlock
}

type ipv6SegmentValues struct {
	value      IPv6SegInt
	upperValue IPv6SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv6SegmentValues) getAddrType() addrType {
	return ipv6Type
}

func (seg *ipv6SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv6SegmentValues) includesMax() bool {
	return seg.upperValue == 0xffff
}

func (seg *ipv6SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv6SegmentValues) getCount() *big.Int {
	return big.NewInt(int64(seg.upperValue-seg.value) + 1)
}

func (seg *ipv6SegmentValues) getBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *ipv6SegmentValues) getByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *ipv6SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv6SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv6SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv6SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value >> 8), byte(seg.value)}

	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue >> 8), byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}

	return
}

func (seg *ipv6SegmentValues) bytesInternal(upper bool) []byte {
	var val IPv6SegInt

	if upper {
		val = seg.upperValue
	} else {
		val = seg.value
	}

	return []byte{byte(val >> 8), byte(val)}
}

func (seg *ipv6SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *ipv6SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) derivePrefixed(prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(seg.value, seg.upperValue, prefLen)
}

func (seg *ipv6SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedVal(IPv6SegInt(val), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func newIPv6SegmentVal(value IPv6SegInt) *ipv6SegmentValues {
	if useIPv6SegmentCache {
		cache := segmentCacheIPv6
		blockIndex := value >> 8 // divide by 0x100
		firstBlockVal := blockIndex << 8
		resultIndex := value - firstBlockVal // mod 0x100
		block := (*ipv6DivsBlock)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache[blockIndex]))))
		//block := cache[blockIndex]
		if block == nil {
			block = &ipv6DivsBlock{make([]ipv6SegmentValues, 0x100)}
			vals := block.block
			for i := range vals {
				item := &vals[i]
				itemVal := firstBlockVal | IPv6SegInt(i)
				item.value = itemVal
				item.upperValue = itemVal
				item.cache.isSinglePrefBlock = &falseVal
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[blockIndex]))
			atomicStorePointer(dataLoc, unsafe.Pointer(block))
		}
		result := &block.block[resultIndex]
		return result
	}

	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
}

func newIPv6SegmentPrefixedVal(value IPv6SegInt, prefLen PrefixLen) (result *ipv6SegmentValues) {
	var isSinglePrefBlock *bool

	if prefLen == nil {
		return newIPv6SegmentVal(value)
	}

	prefixIndex := prefLen.bitCount()
	if prefixIndex < 0 {
		prefixIndex = 0
	} else if prefixIndex > IPv6BitsPerSegment {
		prefixIndex = IPv6BitsPerSegment
	}

	prefLen = cacheBitCount(prefixIndex) // use the prefix length cache for all segments

	if useIPv6SegmentCache {
		cache := segmentPrefixCacheIPv6
		prefixCache := (*ipv6DivsPartition)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))))
		if prefixCache == nil {
			prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, (IPv6MaxValuePerSegment>>8)+1)}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
			atomicStorePointer(dataLoc, unsafe.Pointer(prefixCache))
		}
		blockIndex := value >> 8 // divide by 0x100
		firstBlockVal := blockIndex << 8
		resultIndex := value - (firstBlockVal) // mod 0x100
		blockCache := (*ipv6DivsBlock)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))))
		if blockCache == nil {
			blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, (IPv6MaxValuePerSegment>>8)+1)}
			vals := blockCache.block
			var isSinglePrefBlock *bool
			if prefixIndex == IPv6BitsPerSegment {
				isSinglePrefBlock = &trueVal
			} else {
				isSinglePrefBlock = &falseVal
			}
			for i := range vals {
				item := &vals[i]
				itemVal := firstBlockVal | IPv6SegInt(i)
				item.value = itemVal
				item.upperValue = itemVal
				item.prefLen = prefLen
				item.cache.isSinglePrefBlock = isSinglePrefBlock
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))
			atomicStorePointer(dataLoc, unsafe.Pointer(blockCache))
		}
		result := &blockCache.block[resultIndex]
		return result
	}

	if prefixIndex == IPv6BitsPerSegment {
		isSinglePrefBlock = &trueVal
	} else {
		isSinglePrefBlock = &falseVal
	}

	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

func makePrefixCacheIPv6() (allPrefixedCacheIPv6 []ipv6SegmentValues) {
	if useIPv6SegmentCache {
		allPrefixedCacheIPv6 = make([]ipv6SegmentValues, IPv6BitsPerSegment+1)
		for i := range allPrefixedCacheIPv6 {
			vals := &allPrefixedCacheIPv6[i]
			vals.upperValue = IPv6MaxValuePerSegment
			vals.prefLen = cacheBitCount(i)
			vals.cache.isSinglePrefBlock = &falseVal
		}
		allPrefixedCacheIPv6[0].cache.isSinglePrefBlock = &trueVal
	}
	return
}

func newIPv6SegmentPrefixedValues(value, upperValue IPv6SegInt, prefLen PrefixLen) *ipv6SegmentValues {
	var isSinglePrefBlock *bool

	if prefLen == nil {
		if value == upperValue {
			return newIPv6SegmentVal(value)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		if useIPv6SegmentCache && value == 0 && upperValue == IPv6MaxValuePerSegment {
			return allRangeValsIPv6
		}
		isSinglePrefBlock = &falseVal
	} else {
		if value == upperValue {
			return newIPv6SegmentPrefixedVal(value, prefLen)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}

		prefixIndex := prefLen.bitCount()
		if prefixIndex < 0 {
			prefixIndex = 0
		} else if prefixIndex > IPv6BitsPerSegment {
			prefixIndex = IPv6BitsPerSegment
		}

		prefLen = cacheBitCount(prefixIndex) // this ensures we use the prefix length cache for all segments

		if useIPv6SegmentCache {
			shiftBits := uint(IPv6BitsPerSegment - prefixIndex)
			nmask := ^IPv6SegInt(0) << shiftBits
			prefixBlockLower := value & nmask
			hmask := ^nmask
			prefixBlockUpper := value | hmask
			if value == prefixBlockLower && upperValue == prefixBlockUpper {
				// cache is the prefix block for any prefix length
				cache := prefixBlocksCacheIPv6
				prefixCache := (*ipv6DivsPartition)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))))
				if prefixCache == nil {
					if prefixIndex <= 8 { // 1 block of size (1 << prefix)
						prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, 1)}
					} else { // (1 << (prefix - 8)) blocks of size 0x100.
						prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, 1<<uint(prefixIndex-8))}
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
					atomicStorePointer(dataLoc, unsafe.Pointer(prefixCache))
				}
				valueIndex := value >> shiftBits
				blockIndex := valueIndex >> 8 // divide by 0x100
				firstBlockVal := blockIndex << 8
				resultIndex := valueIndex - (firstBlockVal) // mod 0x100
				blockCache := (*ipv6DivsBlock)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))))
				if blockCache == nil {
					if prefixIndex <= 8 { // 1 block of size (1 << prefix)
						blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, 1<<uint(prefixIndex))}
					} else { // (1 << (prefix - 8)) blocks of size 0x100.
						blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, 1<<8)}
					}
					vals := blockCache.block
					for i := range vals {
						item := &vals[i]
						itemVal := (firstBlockVal | IPv6SegInt(i)) << shiftBits
						item.value = itemVal
						item.upperValue = itemVal | hmask
						item.prefLen = prefLen
						item.cache.isSinglePrefBlock = &trueVal
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))
					atomicStorePointer(dataLoc, unsafe.Pointer(blockCache))
				}

				return &blockCache.block[resultIndex]
			}

			if value == 0 {
				// cache is 0-0xffff for any prefix length
				if upperValue == IPv6MaxValuePerSegment {
					return &allPrefixedCacheIPv6[prefixIndex]
				}
			}

			isSinglePrefBlock = &falseVal
		}
	}

	return &ipv6SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

// WrapIPv6SegmentValueProvider converts the given IPv6SegmentValueProvider to a SegmentValueProvider.
func WrapIPv6SegmentValueProvider(f IPv6SegmentValueProvider) SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) SegInt {
		return SegInt(f(segmentIndex))
	}
}
