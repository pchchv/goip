package goip

import (
	"fmt"
	"sync/atomic"
	"unsafe"
)

func nilString() string {
	return "<nil>"
}

// nilSection prints a string for sections with a nil division slice or division slice of 0 length.
// For division groupings, the division slice string is generated from using the slice, see toString() or defaultFormat() in grouping code.
func nilSection() string {
	return ""
}

func cloneBytes(orig []byte) []byte {
	return append(make([]byte, 0, len(orig)), orig...)
}

// getBytesCopy copies cached into bytes, unless bytes is too small, in which case cached is cloned.
func getBytesCopy(bytes, cached []byte) []byte {
	if bytes == nil || len(bytes) < len(cached) {
		return cloneBytes(cached)
	}

	copy(bytes, cached)

	return bytes[:len(cached)]
}

func atomicLoadPointer(dataLoc *unsafe.Pointer) unsafe.Pointer {
	return atomic.LoadPointer(dataLoc)
}

func atomicStorePointer(dataLoc *unsafe.Pointer, val unsafe.Pointer) {
	atomic.StorePointer(dataLoc, val)
}

func umin(a, b uint) uint {
	if a < b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minSegInt(a, b SegInt) SegInt {
	if a < b {
		return a
	}
	return b
}

func maxSegInt(a, b SegInt) SegInt {
	if a > b {
		return a
	}
	return b
}

func flagsFromState(state fmt.State, verb rune) string {
	flags := "# +-0"
	vals := make([]rune, 0, len(flags)+5) // %, flags, width, '.', precision, verb
	vals = append(vals, '%')

	for i := 0; i < len(flags); i++ {
		b := flags[i]
		if state.Flag(int(b)) {
			vals = append(vals, rune(b))
		}
	}

	width, widthOK := state.Width()
	precision, precisionOK := state.Precision()

	if widthOK || precisionOK {
		var wpv string
		if widthOK && precisionOK {
			wpv = fmt.Sprintf("%d.%d%c", width, precision, verb)
		} else if widthOK {
			wpv = fmt.Sprintf("%d%c", width, verb)
		} else {
			wpv = fmt.Sprintf(".%d%c", precision, verb)
		}
		return string(vals) + wpv
	}

	vals = append(vals, verb)

	return string(vals)
}

func cloneInts(orig []int) []int {
	return append(make([]int, 0, len(orig)), orig...)
}

func cloneDivs(orig []*AddressDivision) []*AddressDivision {
	return append(make([]*AddressDivision, 0, len(orig)), orig...)
}

func cloneLargeDivs(orig []*IPAddressLargeDivision) []*IPAddressLargeDivision {
	return append(make([]*IPAddressLargeDivision, 0, len(orig)), orig...)
}

func fillDivs(orig []*AddressDivision, val *AddressDivision) {
	for i := range orig {
		orig[i] = val
	}
}
