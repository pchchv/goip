package goip

import (
	"strings"
	"unsafe"
)

const (
	digits              = "0123456789abcdefghijklmnopqrstuvwxyz"
	extendedDigits      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
	uppercaseDigits     = extendedDigits
	doubleDigitsDecimal = "00010203040506070809" +
		"10111213141516171819" +
		"20212223242526272829" +
		"30313233343536373839" +
		"40414243444546474849" +
		"50515253545556575859" +
		"60616263646566676869" +
		"70717273747576777879" +
		"80818283848586878889" +
		"90919293949596979899"
)

var maxDigitMap = createDigitMap()

func getRangeString(
	strProvider divStringProvider,
	rangeSeparator string,
	lowerLeadingZerosCount,
	upperLeadingZerosCount int,
	stringPrefix string,
	radix int,
	uppercase,
	maskUpper bool,
	appendable *strings.Builder) int {

	prefLen := len(stringPrefix)
	hasStringPrefix := prefLen > 0
	if appendable == nil {
		count := lowerLeadingZerosCount + upperLeadingZerosCount +
			strProvider.getLowerStringLength(radix) + strProvider.getUpperStringLength(radix) + len(rangeSeparator)
		if hasStringPrefix {
			count += prefLen << 1
		}
		return count
	} else {
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if lowerLeadingZerosCount > 0 {
			getLeadingZeros(lowerLeadingZerosCount, appendable)
		}
		strProvider.getLowerString(radix, uppercase, appendable)
		appendable.WriteString(rangeSeparator)
		if hasStringPrefix {
			appendable.WriteString(stringPrefix)
		}
		if upperLeadingZerosCount > 0 {
			getLeadingZeros(upperLeadingZerosCount, appendable)
		}
		if maskUpper {
			strProvider.getUpperStringMasked(radix, uppercase, appendable)
		} else {
			strProvider.getUpperString(radix, uppercase, appendable)
		}
	}
	return 0
}

func getDigitCount(value uint64, radix int) int {
	result := 1
	if radix == 16 {
		for {
			value >>= 4
			if value == 0 {
				break
			}
			result++
		}
	} else {
		if radix == 10 {
			if value < 10 {
				return 1
			} else if value < 100 {
				return 2
			} else if value < 1000 {
				return 3
			}
			value /= 1000
			result = 3 // start with 3 in the loop below
		} else if radix == 8 {
			for {
				value >>= 3
				if value == 0 {
					break
				}
				result++
			}
			return result
		}
		rad64 := uint64(radix)
		for {
			value /= rad64
			if value == 0 {
				break
			}
			result++
		}
	}
	return result
}

func createDigitMap() *map[uint64]int {
	res := make(map[uint64]int)
	return &res
}

func getMaxDigitCountCalc(radix int, bitCount BitCount, calc func() int) int {
	rad64 := uint64(radix)
	key := (rad64 << 32) | uint64(bitCount)
	theMapPtr := (*map[uint64]int)(atomicLoadPointer((*unsafe.Pointer)(unsafe.Pointer(&maxDigitMap))))
	theMap := *theMapPtr
	if digs, ok := theMap[key]; ok {
		return digs
	}
	digs := calc()
	newMaxDigitMap := createDigitMap()
	theNewMap := *newMaxDigitMap

	for k, val := range theMap {
		theNewMap[k] = val
	}

	theNewMap[key] = digs
	dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&maxDigitMap))
	atomicStorePointer(dataLoc, unsafe.Pointer(newMaxDigitMap))

	return digs
}

func getMaxDigitCount(radix int, bitCount BitCount, maxValue uint64) int {
	return getMaxDigitCountCalc(radix, bitCount, func() int {
		return getDigitCount(maxValue, radix)
	})
}

func buildDefaultRangeString(strProvider divStringProvider, radix int) string {
	builder := strings.Builder{}
	builder.Grow(20)
	getRangeString(strProvider, RangeSeparatorStr, 0, 0, "", radix, false, false, &builder)
	return builder.String()
}

func getDefaultRangeStringVals(strProvider divStringProvider, val1, val2 uint64, radix int) string {
	var len1, len2 int
	var value1, value2 uint

	if radix == 10 {
		if val2 < 10 {
			len2 = 1
		} else if val2 < 100 {
			len2 = 2
		} else if val2 < 1000 {
			len2 = 3
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		value2 = uint(val2)

		if val1 < 10 {
			len1 = 1
		} else if val1 < 100 {
			len1 = 2
		} else if val1 < 1000 {
			len1 = 3
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		value1 = uint(val1)

		charsStr := strings.Builder{}
		charsStr.Grow(len1 + len2 + 1)

		dig := digits
		doubleDig := doubleDigitsDecimal

		var quotient, remainder uint
		var chars []byte

		if val1 < 10 {
			charsStr.WriteByte(dig[value1])
		} else if val1 < 100 {
			digIndex := value1 << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val1 < 200 {
			charsStr.WriteByte('1')
			digIndex := (value1 - 100) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val1 < 300 {
			charsStr.WriteByte('2')
			digIndex := (value1 - 200) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else {
			chars = make([]byte, len2) // note that len2 >= len1
			origLen1 := len1
			for {
				//value == quotient * 10 + remainder
				quotient = (value1 * 0xcccd) >> 19                       //floor of n/10 is floor of ((0xcccd * n / (2 ^ 16)) / (2 ^ 3))
				remainder = value1 - ((quotient << 3) + (quotient << 1)) //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
				len1--
				chars[len1] = dig[remainder]
				value1 = quotient
				if value1 == 0 {
					break
				}
			}
			charsStr.Write(chars[:origLen1])
		}
		charsStr.WriteByte(RangeSeparator)

		if val2 < 10 {
			charsStr.WriteByte(dig[value2])
		} else if val2 < 100 {
			digIndex := value2 << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val2 < 200 {
			charsStr.WriteByte('1')
			digIndex := (value2 - 100) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else if val2 < 300 {
			charsStr.WriteByte('2')
			digIndex := (value2 - 200) << 1
			charsStr.WriteByte(doubleDig[digIndex])
			charsStr.WriteByte(doubleDig[digIndex+1])
		} else {
			origLen2 := len2
			if chars == nil {
				chars = make([]byte, len2)
			}
			for {
				quotient = (value2 * 0xcccd) >> 19
				remainder = value2 - ((quotient << 3) + (quotient << 1))
				len2--
				chars[len2] = dig[remainder]
				value2 = quotient
				if value2 == 0 {
					break
				}
			}
			charsStr.Write(chars[:origLen2])
		}
		return charsStr.String()
	} else if radix == 16 {
		if val2 < 0x10 {
			len2 = 1
		} else if val2 < 0x100 {
			len2 = 2
		} else if val2 < 0x1000 {
			len2 = 3
		} else if val2 < 0x10000 {
			len2 = 4
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}
		if val1 < 0x10 {
			len1 = 1
		} else if val1 < 0x100 {
			len1 = 2
		} else if val1 < 0x1000 {
			len1 = 3
		} else if val1 < 0x10000 {
			len1 = 4
		} else {
			return buildDefaultRangeString(strProvider, radix)
		}

		value1 = uint(val1)
		charsStr := strings.Builder{}
		charsStr.Grow(len1 + len2 + 1)
		dig := digits

		if val1 < 0x10 {
			charsStr.WriteByte(dig[value1])
		} else {
			shift := uint(12)
			for {
				index := (value1 >> shift) & 15
				if index != 0 { // index 0 is digit "0"
					charsStr.WriteByte(dig[index])
					shift -= 4
					for shift > 0 {
						charsStr.WriteByte(dig[(value1>>shift)&15])
						shift -= 4
					}
					break
				}
				shift -= 4
				if shift == 0 {
					break
				}
			}
			charsStr.WriteByte(dig[value1&15])
		}

		charsStr.WriteByte(RangeSeparator)
		value2 = uint(val2)

		if val2 < 0x10 {
			charsStr.WriteByte(dig[value2])
		} else {
			shift := uint(12)
			for {
				index := (value2 >> shift) & 15
				if index != 0 { // index 0 is digit "0"
					charsStr.WriteByte(dig[index])
					shift -= 4
					for shift > 0 {
						charsStr.WriteByte(dig[(value2>>shift)&15])
						shift -= 4
					}
					break
				}
				shift -= 4
				if shift == 0 {
					break
				}
			}
			charsStr.WriteByte(dig[value2&15])
		}
		return charsStr.String()
	}
	return buildDefaultRangeString(strProvider, radix)
}
