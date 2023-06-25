package goip

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
