package goip

var (
	defaultMasker                = extendedMaskerBase{maskerBase{true}}
	defaultNonSequentialMasker   = extendedMaskerBase{}
	defaultOrMasker              = bitwiseOrerBase{true}
	defaultNonSequentialOrMasker = bitwiseOrerBase{}
)

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

// These can be cached by the int used to construct
type fullRangeMasker struct {
	maskerBase
	upperMask    uint64 // upperMask = ~0L >>> fullRangeBit;
	fullRangeBit int
}

// GetMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker fullRangeMasker) GetMaskedLower(value, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedLower(value & ^masker.upperMask, maskValue)
}

// GetMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker fullRangeMasker) GetMaskedUpper(upperValue, maskValue uint64) uint64 {
	return masker.maskerBase.GetMaskedUpper(upperValue|masker.upperMask, maskValue)
}

type extendedMaskerBase struct {
	maskerBase
}

// GetExtendedMaskedLower provides the smallest masked value, which is not necessarily the smallest masked value.
func (masker extendedMaskerBase) GetExtendedMaskedLower(extendedValue, extendedMaskValue uint64) uint64 {
	return extendedValue & extendedMaskValue
}

// GetExtendedMaskedUpper provides the largest masked value, which is not necessarily the largest masked value.
func (masker extendedMaskerBase) GetExtendedMaskedUpper(extendedUpperValue, extendedMaskValue uint64) uint64 {
	return extendedUpperValue & extendedMaskValue
}

type bitwiseOrerBase struct {
	isSequentialVal bool
}

func (masker bitwiseOrerBase) GetOredLower(value, maskValue uint64) uint64 {
	return value | maskValue
}

func (masker bitwiseOrerBase) GetOredUpper(upperValue, maskValue uint64) uint64 {
	return upperValue | maskValue
}

// IsSequential returns whether masking all values in a range results in a consistent set of values.
func (masker bitwiseOrerBase) IsSequential() bool {
	return masker.isSequentialVal
}

type specificValueMasker struct {
	maskerBase
	lower uint64
	upper uint64
}
