package goip

// Masker is used to mask (apply a bitwise combination) the division and segment values.
type Masker interface {
	// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
	GetMaskedLower(value, maskValue uint64) uint64
	// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
	GetMaskedUpper(upperValue, maskValue uint64) uint64
	// IsSequential returns whether masking all values in a range results in a consistent set of values.
	IsSequential() bool
}

type maskerBase struct {
	isSequentialVal bool
}

// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker maskerBase) GetMaskedLower(value, maskValue uint64) uint64 {
	return value & maskValue
}

// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker maskerBase) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return upperValue & maskValue
}

// IsSequential returns whether masking all values in a range results in a consistent set of values.
func (masker maskerBase) IsSequential() bool {
	return masker.isSequentialVal
}
