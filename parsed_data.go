package goip

const (
	segmentDataSize     = 16
	ipv4SegmentDataSize = segmentDataSize * 4
	ipv6SegmentDataSize = segmentDataSize * 8
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
