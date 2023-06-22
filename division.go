package goip

import "github.com/pchchv/goip/address_string"

var (
	// Wildcards are different, here we only use the range, since the div size is not implicit.
	octalParamsDiv   = new(address_string.IPStringOptionsBuilder).SetRadix(8).SetSegmentStrPrefix(OctalPrefix).SetWildcards(rangeWildcard).ToOptions()
	hexParamsDiv     = new(address_string.IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).SetWildcards(rangeWildcard).ToOptions()
	decimalParamsDiv = new(address_string.IPStringOptionsBuilder).SetRadix(10).SetWildcards(rangeWildcard).ToOptions()
)

// DivInt is an integer type for holding generic division values,
// which can be larger than segment values.
type DivInt = uint64

type divIntVals interface {
	// getDivisionValue gets the lower value for a division
	getDivisionValue() DivInt
	// getUpperDivisionValue gets the upper value for a division
	getUpperDivisionValue() DivInt
}

type divderiver interface {
	// deriveNew produces a new division with the same bit count as the old,
	// but with the new values and prefix length
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues
	// derivePrefixed produces a new division with the same bit count and values as the old,
	// but with the new prefix length
	derivePrefixed(prefLen PrefixLen) divisionValues
}

type addressDivisionInternal struct {
	addressDivisionBase
}

func (div *addressDivisionInternal) isPrefixed() bool {
	return div.getDivisionPrefixLength() != nil
}

func (div *addressDivisionInternal) getDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getDivisionValue()
}

func (div *addressDivisionInternal) getUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperDivisionValue()
}

func (div *addressDivisionInternal) matches(value DivInt) bool {
	return !div.isMultiple() && value == div.getDivisionValue()
}
