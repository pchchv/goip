package goip

const (
	MACBitsPerSegment                             = 8
	MACBytesPerSegment                            = 1
	MACDefaultTextualRadix                        = 16
	MACMaxValuePerSegment                         = 0xff
	MACMaxValuePerDottedSegment                   = 0xffff
	MediaAccessControlSegmentCount                = 6
	MediaAccessControlDottedSegmentCount          = 3
	MediaAccessControlDotted64SegmentCount        = 4
	ExtendedUniqueIdentifier48SegmentCount        = MediaAccessControlSegmentCount
	ExtendedUniqueIdentifier64SegmentCount        = 8
	MACOrganizationalUniqueIdentifierSegmentCount = 3
	MACSegmentMaxChars                            = 2
	MACDashSegmentSeparator                       = '-'
	MACColonSegmentSeparator                      = ':'
	MacSpaceSegmentSeparator                      = ' '
	MacDottedSegmentSeparator                     = '.'
	MacDashedSegmentRangeSeparator                = '|'
	MacDashedSegmentRangeSeparatorStr             = "|"
	macBitsToSegmentBitshift                      = 3
)

func getMacSegCount(isExtended bool) (segmentCount int) {
	if isExtended {
		segmentCount = ExtendedUniqueIdentifier64SegmentCount
	} else {
		segmentCount = MediaAccessControlSegmentCount
	}
	return
}
