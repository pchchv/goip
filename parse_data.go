package goip

const (
	dot             = '.'
	dash            = '-'
	colon           = ':'
	space           = ' '
	upperAdjustment = 8
	// These are for the flags.
	// A standard string is a string showing only the lower value of a segment, in lowercase.
	// A standard range string shows both values, low to high, with the standard separator.
	keyRadix                 uint32 = 0x00ff
	keyBitSize               uint32 = 0xff00
	keyWildcard              uint32 = 0x10000
	keyStandardStr           uint32 = 0x40000
	keyMergedMixed           uint32 = 0x800000
	keyRangeWildcard         uint32 = 0x100000
	keySingleWildcard        uint32 = 0x20000
	keyStandardRangeStr      uint32 = 0x80000
	keyInferredLowerBoundary uint32 = 0x200000
	keyInferredUpperBoundary uint32 = 0x400000
	bitSizeShift                    = 8
	// the flags, radix and bit size are stored in the same int, the radix takes the low byte,
	// the bit size the next byte, the remaining 16 bits are available for flags.
	flagsIndex         = keyLowerRadixIndex
	keyBitSizeIndex    = keyLowerRadixIndex
	keyLowerRadixIndex = 0
	keyUpperRadixIndex = keyLowerRadixIndex + upperAdjustment
	// these are for the segment values - they must be even-numbered
	keyLower         = 2
	keyUpper         = keyLower + upperAdjustment
	keyExtendedLower = 4
	keyExtendedUpper = keyExtendedLower + upperAdjustment
	// these are for the indices
	segmentDataSize        = 16
	segmentIndexShift      = 4
	keyLowerStrEndIndex    = 7
	keyUpperStrEndIndex    = keyLowerStrEndIndex + upperAdjustment
	keyLowerStrStartIndex  = 6
	keyUpperStrStartIndex  = keyLowerStrStartIndex + upperAdjustment
	keyLowerStrDigitsIndex = 1
	keyUpperStrDigitsIndex = keyLowerStrDigitsIndex + upperAdjustment
	ipv4SegmentDataSize    = segmentDataSize * 4
	ipv6SegmentDataSize    = segmentDataSize * 8
)

var (
	dotByte        byte      = dot
	colonByte      byte      = colon
	spaceByte      byte      = space
	dashedByte     byte      = dash
	dashed         macFormat = &dashedByte
	dotted         macFormat = &dotByte
	colonDelimited macFormat = &colonByte
	spaceDelimited macFormat = &spaceByte
	unknownFormat  macFormat
)

type macFormat *byte

type addressParseData struct {
	segmentData                []uint32
	segmentCount               int
	anyWildcard                bool
	isEmpty                    bool
	isAllVal                   bool
	isSingleSegmentVal         bool
	consecutiveSepIndex        int // indices into the original string used while parsing
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

func (parseData *addressParseData) getIndex(segmentIndex, indexIndicator int) int {
	return getIndexFromData(segmentIndex, indexIndicator, parseData.getSegmentData())
}

func (parseData *addressParseData) getValue(segmentIndex, indexIndicator int) uint64 {
	return getValueFromData(segmentIndex, indexIndicator, parseData.getSegmentData())
}

func (parseData *addressParseData) set7IndexFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6
}

func (parseData *addressParseData) set8IndexFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6
	segmentData[baseIndex|indexIndicator7] = value7
}

func (parseData *addressParseData) set8Index4ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64,
	indexIndicator10 int, value10 uint64,
	indexIndicator11 int, value11 uint64) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator8, value8,
		indexIndicator9, value9)
	segmentData[baseIndex|indexIndicator7] = value7

	index := baseIndex | indexIndicator10
	segmentData[index] = uint32(value10 >> 32)
	segmentData[index|1] = uint32(value10 & 0xffffffff)

	index = baseIndex | indexIndicator11
	segmentData[index] = uint32(value11 >> 32)
	segmentData[index|1] = uint32(value11 & 0xffffffff)
}

func (parseData *addressParseData) set7Index4ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64,
	indexIndicator10 int, value10 uint64) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator7, value7,
		indexIndicator8, value8)

	index := baseIndex | indexIndicator9
	segmentData[index] = uint32(value9 >> 32)
	segmentData[index|1] = uint32(value9 & 0xffffffff)

	index = baseIndex | indexIndicator10
	segmentData[index] = uint32(value10 >> 32)
	segmentData[index|1] = uint32(value10 & 0xffffffff)
}

func (parseData *addressParseData) set8Index2ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint32,
	indexIndicator8 int, value8 uint64,
	indexIndicator9 int, value9 uint64) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator8, value8,
		indexIndicator9, value9)
	segmentData[baseIndex|indexIndicator7] = value7
}

func (parseData *addressParseData) set7Index2ValuesFlags(segmentIndex,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64) {
	baseIndex := segmentIndex << segmentIndexShift
	segmentData := parseData.getSegmentData()
	setIndexValuesFlags(baseIndex, segmentData,
		indexIndicator0, value0,
		indexIndicator1, value1,
		indexIndicator2, value2,
		indexIndicator3, value3,
		indexIndicator4, value4,
		indexIndicator5, value5,
		indexIndicator6, value6,
		indexIndicator7, value7,
		indexIndicator8, value8)
}

func (parseData *addressParseData) setValue(segmentIndex,
	indexIndicator int, value uint64) {
	index := (segmentIndex << segmentIndexShift) | indexIndicator
	upperValue := uint32(value >> 32)
	lowerValue := uint32(value & 0xffffffff)
	segmentData := parseData.getSegmentData()
	segmentData[index] = upperValue
	segmentData[index|1] = lowerValue
}

func (parseData *addressParseData) isMergedMixed(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, keyMergedMixed)
}

func (parseData *addressParseData) isWildcard(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, keyWildcard)
}

func (parseData *addressParseData) hasRange(segmentIndex int) bool {
	return parseData.hasEitherFlag(segmentIndex, keySingleWildcard, keyRangeWildcard)
}

func (parseData *addressParseData) isInferredUpperBoundary(segmentIndex int) bool {
	return parseData.getFlag(segmentIndex, keyInferredUpperBoundary)
}

type ipAddressParseData struct {
	addressParseData
	qualifier              parsedHostIdentifierStringQualifier
	qualifierIndex         int
	hasPrefixSeparatorVal  bool
	isZonedVal             bool
	ipVersion              IPVersion
	isInetAtonJoinedVal    bool
	hasInetAtonValueVal    bool // either octal 01 or hex 0x1
	hasIPv4LeadingZerosVal bool
	isBinaryVal            bool
	isBase85               bool
	isBase85ZonedVal       bool
	mixedParsedAddress     *parsedIPAddress
}

func (parseData *ipAddressParseData) init(str string) {
	parseData.qualifierIndex = -1
	parseData.addressParseData.init(str)
}

func (parseData *ipAddressParseData) getAddressParseData() *addressParseData {
	return &parseData.addressParseData
}

func (parseData *ipAddressParseData) getProviderIPVersion() IPVersion {
	return parseData.ipVersion
}

func (parseData *ipAddressParseData) clearQualifier() {
	parseData.qualifierIndex = -1
	parseData.isZonedVal = false
	parseData.isBase85ZonedVal = false
	parseData.hasPrefixSeparatorVal = false
	parseData.qualifier = parsedHostIdentifierStringQualifier{}
}

func (parseData *ipAddressParseData) setVersion(version IPVersion) {
	parseData.ipVersion = version
}

func (parseData *ipAddressParseData) setInetAtonJoined(val bool) {
	parseData.isInetAtonJoinedVal = val
}

func (parseData *ipAddressParseData) isProvidingIPv6() bool {
	version := parseData.getProviderIPVersion()
	return version.IsIPv6()
}

func (parseData *ipAddressParseData) isProvidingIPv4() bool {
	version := parseData.getProviderIPVersion()
	return version.IsIPv4()
}

func (parseData *ipAddressParseData) isInetAtonJoined() bool {
	return parseData.isInetAtonJoinedVal
}

func (parseData *ipAddressParseData) hasInetAtonValue() bool {
	return parseData.hasInetAtonValueVal
}

func (parseData *ipAddressParseData) setHasInetAtonValue(val bool) {
	parseData.hasInetAtonValueVal = val
}

func (parseData *ipAddressParseData) setHasIPv4LeadingZeros(val bool) {
	parseData.hasIPv4LeadingZerosVal = val
}

func (parseData *ipAddressParseData) hasIPv4LeadingZeros() bool {
	return parseData.hasIPv4LeadingZerosVal
}

func (parseData *ipAddressParseData) hasBinaryDigits() bool {
	return parseData.isBinaryVal
}

func (parseData *ipAddressParseData) setHasBinaryDigits(val bool) {
	parseData.isBinaryVal = val
}

func (parseData *ipAddressParseData) setQualifierIndex(index int) {
	parseData.qualifierIndex = index
}

func (parseData *ipAddressParseData) getQualifier() *parsedHostIdentifierStringQualifier {
	return &parseData.qualifier
}

func (parseData *ipAddressParseData) getQualifierIndex() int {
	return parseData.qualifierIndex
}

func (parseData *ipAddressParseData) isZoned() bool {
	return parseData.isZonedVal
}

func (parseData *ipAddressParseData) setZoned(val bool) {
	parseData.isZonedVal = val
}

func (parseData *ipAddressParseData) hasPrefixSeparator() bool {
	return parseData.hasPrefixSeparatorVal
}

func (parseData *ipAddressParseData) setHasPrefixSeparator(val bool) {
	parseData.hasPrefixSeparatorVal = val
}

func (parseData *ipAddressParseData) isProvidingBase85IPv6() bool {
	return parseData.isBase85
}

func (parseData *ipAddressParseData) setBase85(val bool) {
	parseData.isBase85 = val
}

func (parseData *ipAddressParseData) isBase85Zoned() bool {
	return parseData.isBase85ZonedVal
}

func (parseData *ipAddressParseData) setBase85Zoned(val bool) {
	parseData.isBase85ZonedVal = val
}

func (parseData *ipAddressParseData) isCompressed() bool {
	return parseData.addressParseData.getConsecutiveSeparatorIndex() >= 0
}

func (parseData *ipAddressParseData) segIsCompressed(index int, segmentData []uint32) bool {
	end := getIndexFromData(index, keyUpperStrEndIndex, segmentData)
	start := getIndexFromData(index, keyLowerStrStartIndex, segmentData)
	return start == end
}

func (parseData *ipAddressParseData) segmentIsCompressed(index int) bool {
	return parseData.segIsCompressed(index, parseData.addressParseData.getSegmentData())
}

func (parseData *ipAddressParseData) isProvidingMixedIPv6() bool {
	return parseData.mixedParsedAddress != nil
}

func (parseData *ipAddressParseData) setMixedParsedAddress(val *parsedIPAddress) {
	parseData.mixedParsedAddress = val
}

type macAddressParseData struct {
	addressParseData
	isDoubleSegmentVal bool
	isExtendedVal      bool
	format             macFormat
}

func (parseData *macAddressParseData) init(str string) {
	parseData.addressParseData.init(str)
}

func (parseData *macAddressParseData) getAddressParseData() *addressParseData {
	return &parseData.addressParseData
}

func (parseData *macAddressParseData) getFormat() macFormat {
	return parseData.format
}

func (parseData *macAddressParseData) setFormat(format macFormat) {
	parseData.format = format
}

func (parseData *macAddressParseData) isDoubleSegment() bool {
	return parseData.isExtendedVal
}

func (parseData *macAddressParseData) setDoubleSegment(val bool) {
	parseData.isExtendedVal = val
}

func (parseData *macAddressParseData) isExtended() bool {
	return parseData.isDoubleSegmentVal
}

func (parseData *macAddressParseData) setExtended(val bool) {
	parseData.isDoubleSegmentVal = val
}

func getIndexFromData(segmentIndex, indexIndicator int, segmentData []uint32) int {
	return int(segmentData[(segmentIndex<<segmentIndexShift)|indexIndicator])
}

func getValueFromData(segmentIndex, indexIndicator int, segmentData []uint32) uint64 {
	index := (segmentIndex << segmentIndexShift) | indexIndicator
	upperValue := uint64(segmentData[index])
	lowerValue := 0xffffffff & uint64(segmentData[index|1])
	value := (upperValue << 32) | lowerValue
	return value
}

func setIndexValuesFlags(
	baseIndex int,
	segmentData []uint32,
	indexIndicator0 int, value0 uint32,
	indexIndicator1 int, value1 uint32,
	indexIndicator2 int, value2 uint32,
	indexIndicator3 int, value3 uint32,
	indexIndicator4 int, value4 uint32,
	indexIndicator5 int, value5 uint32,
	indexIndicator6 int, value6 uint32,
	indexIndicator7 int, value7 uint64,
	indexIndicator8 int, value8 uint64) {
	segmentData[baseIndex|indexIndicator0] = value0
	segmentData[baseIndex|indexIndicator1] = value1
	segmentData[baseIndex|indexIndicator2] = value2
	segmentData[baseIndex|indexIndicator3] = value3
	segmentData[baseIndex|indexIndicator4] = value4
	segmentData[baseIndex|indexIndicator5] = value5
	segmentData[baseIndex|indexIndicator6] = value6

	index := baseIndex | indexIndicator7
	segmentData[index] = uint32(value7 >> 32)
	segmentData[index|1] = uint32(value7 & 0xffffffff)

	index = baseIndex | indexIndicator8
	segmentData[index] = uint32(value8 >> 32)
	segmentData[index|1] = uint32(value8 & 0xffffffff)
}
