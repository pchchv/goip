package goip

import "github.com/pchchv/goip/address_error"

// AddressComponent represents all addresses, address sections and address segments.
type AddressComponent interface { //AddressSegment and above, AddressSegmentSeries and above
	// TestBit returns true if the bit in the lowest value of the address component by the given index is 1,
	// where index 0 refers to the lowest significant bit. In other words, it calculates (bits & (1 << n) != 0),
	// using the lowest value of this address component. TestBit panics if n < 0,
	// or if it matches or exceeds the number of bits of this address component.
	TestBit(index BitCount) bool
	// IsOneBit returns true if the bit in the lowest value of this address component by the given index is 1, where index 0 refers to the highest bit.
	// IsOneBit causes a panic if bitIndex is less than zero, or if it is greater than the number of bits of this address component.
	IsOneBit(index BitCount) bool
	// ToHexString writes this address component as a single hex value
	// (possibly two values if the range is not a prefix block),
	// the number of digits according to the number of bits,
	// with or without the preceding "0x" prefix.
	// If a multi-digit component cannot be written as a single prefix block or
	// a range of two values, an error is returned.
	ToHexString(with0xPrefix bool) (string, address_error.IncompatibleAddressError)
	// ToNormalizedString creates a string that is consistent for
	// all address components of the same type and version.
	ToNormalizedString() string
}
