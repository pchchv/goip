package goip

type seriesStack struct {
	seriesPairs []ExtendedIPSegmentSeries
	indexes     []int
	bits        []BitCount
}

// init grows to have capacity at least as large as size.
func (stack *seriesStack) init(size int) {
	if stack.seriesPairs == nil {
		stack.seriesPairs = make([]ExtendedIPSegmentSeries, 0, size<<1)
		stack.indexes = make([]int, 0, size)
		stack.bits = make([]BitCount, 0, size)
	}
}

func (stack *seriesStack) push(lower, upper ExtendedIPSegmentSeries, previousSegmentBits BitCount, currentSegment int) {
	stack.seriesPairs = append(stack.seriesPairs, lower, upper)
	stack.indexes = append(stack.indexes, currentSegment)
	stack.bits = append(stack.bits, previousSegmentBits)
}

func (stack *seriesStack) pop() (popped bool, lower, upper ExtendedIPSegmentSeries, previousSegmentBits BitCount, currentSegment int) {
	seriesPairs := stack.seriesPairs
	length := len(seriesPairs)
	if length <= 0 {
		return
	}

	length--
	upper = seriesPairs[length]
	length--
	lower = seriesPairs[length]
	stack.seriesPairs = seriesPairs[:length]
	indexes := stack.indexes
	length = len(indexes) - 1
	currentSegment = indexes[length]
	stack.indexes = indexes[:length]
	stackbits := stack.bits
	previousSegmentBits = stackbits[length]
	stack.bits = stackbits[:length]
	popped = true
	return
}

func checkPrefixBlockFormat(container, contained ExtendedIPSegmentSeries, checkEqual bool) (result ExtendedIPSegmentSeries) {
	if container.IsPrefixed() && container.IsSinglePrefixBlock() {
		result = container
	} else if checkEqual && contained.IsPrefixed() && container.CompareSize(contained) == 0 && contained.IsSinglePrefixBlock() {
		result = contained
	} else {
		result = container.AssignPrefixForSingleBlock() // this returns nil if cannot be a prefix block
	}
	return
}

func checkPrefixBlockContainment(first, other ExtendedIPSegmentSeries) ExtendedIPSegmentSeries {
	if first.Contains(other) {
		return checkPrefixBlockFormat(first, other, true)
	} else if other.Contains(first) {
		return checkPrefixBlockFormat(other, first, false)
	}
	return nil
}

func applyOperatorToLowerUpper(first, other ExtendedIPSegmentSeries, removePrefixes bool,
	operatorFunctor func(lower, upper ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	var lower, upper ExtendedIPSegmentSeries
	if seriesValsSame(first, other) {
		if removePrefixes && first.IsPrefixed() {
			if other.IsPrefixed() {
				lower = first.WithoutPrefixLen()
			} else {
				lower = other
			}
		} else {
			lower = first
		}
		upper = lower.GetUpper()
		lower = lower.GetLower()
	} else {
		firstLower := first.GetLower()
		otherLower := other.GetLower()
		firstUpper := first.GetUpper()
		otherUpper := other.GetUpper()
		if LowValueComparator.CompareSeries(firstLower, otherLower) > 0 {
			lower = otherLower
		} else {
			lower = firstLower
		}
		if LowValueComparator.CompareSeries(firstUpper, otherUpper) < 0 {
			upper = otherUpper
		} else {
			upper = firstUpper
		}
		if removePrefixes {
			lower = lower.WithoutPrefixLen()
			upper = upper.WithoutPrefixLen()
		}
	}
	return operatorFunctor(lower, upper)
}
