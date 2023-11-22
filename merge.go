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

func getMergedPrefixBlocks(sections []ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	singleElement, list := organizeSequentially(sections)
	if singleElement {
		return list
	}

	removedCount := 0
	listLen := len(list)
	first := sections[0]
	bitCount := first.GetBitCount()
	bitsPerSegment := first.GetBitsPerSegment()
	bytesPerSegment := first.GetBytesPerSegment()
	j := listLen - 1
	i := j - 1
top:
	for j > 0 {
		item := list[i]
		otherItem := list[j]
		compare := ReverseHighValueComparator.CompareSeries(item, otherItem)
		// check for strict containment, case 1:
		// w   z
		//  x y

		if compare > 0 {
			removedCount++
			k := j + 1
			for k < listLen && list[k] == nil {
				k++
			}
			if k < listLen {
				list[j] = list[k]
				list[k] = nil
			} else {
				list[j] = nil
				j = i
				i--
			}
			continue
		}
		// non-strict containment, case 2:
		// w   z
		// w   z
		//
		// reverse containment, case 3:
		// w  y
		// w   z
		rcompare := ReverseLowValueComparator.CompareSeries(item, otherItem)
		if rcompare >= 0 {
			removedCount++
			list[i] = otherItem
			list[j] = nil
			j = i
			i--
			continue
		}
		// check for merge, case 4:
		// w   x
		//      y   z
		// where x and y adjacent, becoming:
		// w        z
		//
		prefixLen := item.GetPrefixLen()
		otherPrefixLen := otherItem.GetPrefixLen()
		if !prefixLen.Equal(otherPrefixLen) {
			j = i
			i--
			continue
		}

		var matchBitIndex BitCount
		if prefixLen == nil {
			matchBitIndex = bitCount - 1
		} else {
			matchBitIndex = prefixLen.bitCount() - 1
		}

		var lastMatchSegmentIndex, lastBitSegmentIndex int
		if matchBitIndex != 0 {
			lastMatchSegmentIndex = getNetworkSegmentIndex(matchBitIndex, bytesPerSegment, bitsPerSegment)
			lastBitSegmentIndex = getHostSegmentIndex(matchBitIndex, bytesPerSegment, bitsPerSegment)
		}

		itemSegment := item.GetGenericSegment(lastMatchSegmentIndex)
		otherItemSegment := otherItem.GetGenericSegment(lastMatchSegmentIndex)
		itemSegmentValue := itemSegment.GetSegmentValue()
		otherItemSegmentValue := otherItemSegment.GetSegmentValue()
		segmentLastBitIndex := bitsPerSegment - 1
		if lastBitSegmentIndex == lastMatchSegmentIndex {
			segmentBitToCheck := matchBitIndex % bitsPerSegment
			shift := segmentLastBitIndex - segmentBitToCheck
			itemSegmentValue >>= uint(shift)
			otherItemSegmentValue >>= uint(shift)
		} else {
			itemBitValue := item.GetGenericSegment(lastBitSegmentIndex).GetSegmentValue()
			otherItemBitalue := otherItem.GetGenericSegment(lastBitSegmentIndex).GetSegmentValue()

			// we will make space for the last bit so we can do a single comparison
			itemSegmentValue = (itemSegmentValue << 1) | (itemBitValue >> uint(segmentLastBitIndex))
			otherItemSegmentValue = (otherItemSegmentValue << 1) | (otherItemBitalue >> uint(segmentLastBitIndex))
		}

		if itemSegmentValue != otherItemSegmentValue {
			itemSegmentValue ^= 1 // the ^ 1 flips the first bit
			if itemSegmentValue != otherItemSegmentValue {
				// neither an exact match nor a match when flipping the bit, so move on
				j = i
				i--
				continue
			} // else we will merge these two into a single prefix block, presuming the initial segments match
		}

		// check initial segments
		for k := lastMatchSegmentIndex - 1; k >= 0; k-- {
			itemSegment = item.GetGenericSegment(k)
			otherItemSegment = otherItem.GetGenericSegment(k)
			val := itemSegment.GetSegmentValue()
			otherVal := otherItemSegment.GetSegmentValue()
			if val != otherVal {
				j = i
				i--
				continue top
			}
		}

		joinedItem := otherItem.ToPrefixBlockLen(matchBitIndex)
		list[i] = joinedItem
		removedCount++
		k := j + 1
		for k < listLen && list[k] == nil {
			k++
		}

		if k < listLen {
			list[j] = list[k]
			list[k] = nil
		} else {
			list[j] = nil
			j = i
			i--
		}
	}

	if removedCount > 0 {
		newSize := listLen - removedCount
		for k, l := 0, 0; k < newSize; k, l = k+1, l+1 {
			for list[l] == nil {
				l++
			}
			if k != l {
				list[k] = list[l]
			}
		}
		list = list[:newSize]
	}
	return list
}

func organizeSequentialMerge(sections []ExtendedIPSegmentSeries) (singleElement bool, list []ExtendedIPSegmentSeries) {
	for i := 0; i < len(sections); i++ {
		section := sections[i]
		if section == nil {
			continue
		}

		if section.IsSequential() {
			list = append(list, section)
		} else {
			iterator := section.SequentialBlockIterator()
			for iterator.HasNext() {
				list = append(list, iterator.Next())
			}
		}
	}

	if len(list) == 1 {
		singleElement = true
		return
	}

	sort.Slice(list, func(i, j int) bool {
		return LowValueComparator.CompareSeries(list[i], list[j]) < 0
	})
	return
}
