package goip

// MACAddressSection is a section of a MACAddress.
//
// It is a series of 0 to 8 individual MAC address segments.
type MACAddressSection struct {
	addressSectionInternal
}

// IsMultiple returns whether this section represents multiple values.
func (section *MACAddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

// IsPrefixed returns whether this section has an associated prefix length.
func (section *MACAddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}
