package goip

func cloneTo[T any, U any](orig []T, conv func(T) U) []U {
	result := make([]U, len(orig))
	for i := range orig {
		result[i] = conv(orig[i])
	}
	return result
}

func cloneToExtra[T any, U any](sect T, orig []T, conv func(T) U) []U {
	origCount := len(orig)
	result := make([]U, origCount+1)
	result[origCount] = conv(sect)
	for i := range orig {
		result[i] = conv(orig[i])
	}
	return result
}

func copyTo[T any, U any](dest []U, orig []T, conv func(T) U) {
	for i := range orig {
		if i == len(dest) {
			break
		}
		dest[i] = conv(orig[i])
	}
	return
}