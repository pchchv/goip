package goip

// DivisionType serves as a common interface to all divisions
type DivisionType interface {
	AddressItem
	getAddrType() addressType
	// getStringAsLower caches the string from getDefaultLowerString
	getStringAsLower() string
	// GetString produces a string that avoids wildcards when a prefix length is part of the string.
	// Equivalent to GetWildcardString when the prefix length is not part of the string.
	GetString() string
	// GetWildcardString produces a string that uses wildcards and avoids prefix length
	GetWildcardString() string
	// IsSinglePrefix determines if the division has a single prefix for the given prefix length.
	// You can call GetPrefixCountLen to get the count of prefixes.
	IsSinglePrefix(BitCount) bool
	// methods for string generation used by the string params and string writer
	divStringProvider
}
