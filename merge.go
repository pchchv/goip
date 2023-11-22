package goip

import "sort"

func organizeSequentially(sections []ExtendedIPSegmentSeries) (singleElement bool, list []ExtendedIPSegmentSeries) {
	var sequentialList []ExtendedIPSegmentSeries
	length := len(sections)
	for i := 0; i < length; i++ {
		section := sections[i]
		if section == nil {
			continue
		}
		if !section.IsSequential() {
			if sequentialList == nil {
				sequentialList = make([]ExtendedIPSegmentSeries, 0, length)
				for j := 0; j < i; j++ {
					series := sections[j]
					if series != nil {
						sequentialList = append(sequentialList, series)
					}
				}
			}
			iterator := section.SequentialBlockIterator()
			for iterator.HasNext() {
				sequentialList = append(sequentialList, iterator.Next())
			}
		} else if sequentialList != nil {
			sequentialList = append(sequentialList, section)
		}
	}

	if sequentialList == nil {
		sequentialList = sections
	}

	sequentialLen := len(sequentialList)
	for j := 0; j < sequentialLen; j++ {
		series := sequentialList[j]
		if series.IsSinglePrefixBlock() {
			list = append(list, series)
		} else {
			span := series.SpanWithPrefixBlocks()
			list = append(list, span...)
		}
	}

	if len(list) <= 1 {
		return true, list
	}

	sort.Slice(list, func(i, j int) bool {
		return LowValueComparator.CompareSeries(list[i], list[j]) < 0
	})
	return false, list
}
