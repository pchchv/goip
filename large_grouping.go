package goip

type largeDivisionGroupingInternal struct {
	addressDivisionGroupingBase
}

func (grouping *largeDivisionGroupingInternal) calcBytes() (bytes, upperBytes []byte) {
	divisionCount := grouping.GetDivisionCount()
	isMultiple := grouping.isMultiple()
	byteCount := grouping.GetByteCount()
	bytes = make([]byte, byteCount)

	if isMultiple {
		upperBytes = make([]byte, byteCount)
	} else {
		upperBytes = bytes
	}

	for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
		div := grouping.getDivision(k)
		bigBytes := div.getValue().Bytes()
		var bigUpperBytes []byte

		if isMultiple {
			bigUpperBytes = div.getUpperValue().Bytes()
		}

		for totalDivBits := div.GetBitCount(); totalDivBits > 0; totalDivBits -= 64 {
			// grab those 64 bits (from bigBytes and bigUpperBytes) and put them in val and upperVal
			divBits := min(totalDivBits, 64)
			var divBytes []byte
			var val, upperVal uint64

			if len(bigBytes) > 8 {
				byteLen := len(bigBytes) - 8
				divBytes = bigBytes[byteLen:]
				bigBytes = bigBytes[:byteLen]
			} else {
				divBytes = bigBytes
				bigBytes = nil
			}

			for _, b := range divBytes {
				val = (val << 8) | uint64(b)
			}

			if isMultiple {
				var divUpperBytes []byte
				if len(upperBytes) > 8 {
					byteLen := len(bigUpperBytes) - 8
					divUpperBytes = bigBytes[byteLen:]
					bigUpperBytes = bigBytes[:byteLen]
				} else {
					divUpperBytes = bigUpperBytes
					bigUpperBytes = nil
				}

				for _, b := range divUpperBytes {
					upperVal = (upperVal << 8) | uint64(b)
				}
			}

			// insert the 64 bits into the  bytes slice
			for divBits > 0 {
				rbi := 8 - bitIndex
				bytes[byteIndex] |= byte(val << uint(rbi))
				val >>= uint(bitIndex)

				if isMultiple {
					upperBytes[byteIndex] |= byte(upperVal << uint(rbi))
					upperVal >>= uint(bitIndex)
				}

				if divBits < bitIndex {
					// bitIndex is the index into the last copied byte that was already occupied previously
					// so here we were able to copy all the bits and there was still space left over
					bitIndex -= divBits
					break
				} else {
					// we used up all the space available
					// if we also copied all the bits, then divBits will be assigned zero
					// otherwise it will have the number of bits still left to copy
					divBits -= bitIndex
					bitIndex = 8
					byteIndex--
				}
			}
		}
	}
	return
}

func (grouping *largeDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getCachedBytes(grouping.calcBytes)
	return
}

// CopyUpperBytes copies the value of the highest division grouping in the range into a byte slice.
//
// If the value can fit in the given slice, it is copied into that slice and a length-adjusted sub-slice is returned.
// Otherwise, a new slice with the value is created and returned.
//
// You can use the GetByteCount function to determine the required length of the byte array.
func (grouping *largeDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes[:0]
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getUpperBytes())
}
