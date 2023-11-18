package goip

const SegmentValueDelimiter = ','

type DelimitedAddressString string

// CountDelimitedAddresses will count the possible combinations,
// given a string with comma delimiters separating segment elements.
// It is a counterpart to ParseDelimitedSegments,
// indicating the number of iterated elements from ParseDelimitedSegments.
//
// For example, given "1,2.3.4,5.6" this method will return 4 for the possible combinations:
// "1.3.4.6", "1.3.5.6", "2.3.4.6" and "2.3.5.6".
func (str DelimitedAddressString) CountDelimitedAddresses() int {
	segDelimitedCount := 0
	result := 1
	strlen := len(str)
	for i := 0; i < strlen; i++ {
		c := str[i]
		if isDelimitedBoundary(c) {
			if segDelimitedCount > 0 {
				result *= segDelimitedCount + 1
				segDelimitedCount = 0
			}
		} else if c == SegmentValueDelimiter {
			segDelimitedCount++
		}
	}
	if segDelimitedCount > 0 {
		result *= segDelimitedCount + 1
	}
	return result
}

func isDelimitedBoundary(c byte) bool {
	return c == IPv4SegmentSeparator ||
		c == IPv6SegmentSeparator ||
		c == RangeSeparator ||
		c == MacDashedSegmentRangeSeparator
}
