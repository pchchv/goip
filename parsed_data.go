package goip

const (
	keyRadix            uint32 = 0x00ff
	keyBitSize          uint32 = 0xff00
	keyBitSizeIndex            = keyLowerRadixIndex
	keyLowerRadixIndex         = 0
	flagsIndex                 = keyLowerRadixIndex
	bitSizeShift               = 8
	segmentIndexShift          = 4
	segmentDataSize            = 16
	ipv4SegmentDataSize        = segmentDataSize * 4
	ipv6SegmentDataSize        = segmentDataSize * 8
)

type addressParseData struct {
	segmentData                []uint32
	segmentCount               int
	anyWildcard                bool
	isEmpty                    bool
	isAllVal                   bool
	isSingleSegmentVal         bool
	consecutiveSepIndex        int
	consecutiveSepSegmentIndex int
	addressEndIndex            int
	str                        string
}

func (parseData *addressParseData) init(str string) {
	parseData.consecutiveSepIndex = -1
	parseData.consecutiveSepSegmentIndex = -1
	parseData.str = str
}

func (parseData *addressParseData) getString() string {
	return parseData.str
}

func (parseData *addressParseData) initSegmentData(segmentCapacity int) {
	dataSize := 0

	if segmentCapacity == 4 {
		dataSize = ipv4SegmentDataSize
	} else if segmentCapacity == 8 {
		dataSize = ipv6SegmentDataSize
	} else if segmentCapacity == 1 {
		dataSize = segmentDataSize // segmentDataSize * segmentCapacity
	} else {
		dataSize = segmentCapacity * segmentDataSize
	}

	parseData.segmentData = make([]uint32, dataSize)
}

func (parseData *addressParseData) getSegmentData() []uint32 {
	return parseData.segmentData
}

func (parseData *addressParseData) getSegmentCount() int {
	return parseData.segmentCount
}

func (parseData *addressParseData) getConsecutiveSeparatorIndex() int {
	return parseData.consecutiveSepIndex
}

func (parseData *addressParseData) getConsecutiveSeparatorSegmentIndex() int {
	return parseData.consecutiveSepSegmentIndex
}

func (parseData *addressParseData) setConsecutiveSeparatorSegmentIndex(val int) {
	parseData.consecutiveSepSegmentIndex = val
}

func (parseData *addressParseData) setConsecutiveSeparatorIndex(val int) {
	parseData.consecutiveSepIndex = val
}

func (parseData *addressParseData) incrementSegmentCount() {
	parseData.segmentCount++
}

func (parseData *addressParseData) isProvidingEmpty() bool {
	return parseData.isEmpty
}

func (parseData *addressParseData) isAll() bool {
	return parseData.isAllVal
}

func (parseData *addressParseData) setEmpty(val bool) {
	parseData.isEmpty = val
}

func (parseData *addressParseData) setAll() {
	parseData.isAllVal = true
}

func (parseData *addressParseData) getAddressEndIndex() int {
	return parseData.addressEndIndex
}

func (parseData *addressParseData) setAddressEndIndex(val int) {
	parseData.addressEndIndex = val
}

func (parseData *addressParseData) isSingleSegment() bool {
	return parseData.isSingleSegmentVal
}

func (parseData *addressParseData) hasWildcard() bool {
	return parseData.anyWildcard
}

func (parseData *addressParseData) setSingleSegment() {
	parseData.isSingleSegmentVal = true
}

func (parseData *addressParseData) setHasWildcard() {
	parseData.anyWildcard = true
}

func (parseData *addressParseData) unsetFlag(segmentIndex int, flagIndicator uint32) {
	index := (segmentIndex << segmentIndexShift) | flagsIndex
	segmentData := parseData.getSegmentData()
	segmentData[index] &= uint32(0xffff) ^ flagIndicator // segmentData[index] &= ~flagIndicator
}

func (parseData *addressParseData) getFlag(segmentIndex int, flagIndicator uint32) bool {
	segmentData := parseData.getSegmentData()
	return (segmentData[(segmentIndex<<segmentIndexShift)|flagsIndex] & flagIndicator) != 0
}

func (parseData *addressParseData) hasEitherFlag(segmentIndex int, flagIndicator1, flagIndicator2 uint32) bool {
	return parseData.getFlag(segmentIndex, flagIndicator1|flagIndicator2)
}

func (parseData *addressParseData) getRadix(segmentIndex, indexIndicator int) uint32 {
	segmentData := parseData.getSegmentData()
	radix := segmentData[(segmentIndex<<segmentIndexShift)|indexIndicator] & keyRadix
	if radix == 0 {
		return IPv6DefaultTextualRadix // 16 is the default, we only set the radix if not 16
	}
	return radix
}

func (parseData *addressParseData) getBitLength(segmentIndex int) BitCount {
	segmentData := parseData.getSegmentData()
	bitLength := (segmentData[(segmentIndex<<segmentIndexShift)|keyBitSizeIndex] & keyBitSize) >> bitSizeShift
	return BitCount(bitLength)
}

func (parseData *addressParseData) setBitLength(segmentIndex int, length BitCount) {
	segmentData := parseData.getSegmentData()
	segmentData[(segmentIndex<<segmentIndexShift)|keyBitSizeIndex] |= (uint32(length) << bitSizeShift) & keyBitSize
}

func (parseData *addressParseData) setIndex(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
}
