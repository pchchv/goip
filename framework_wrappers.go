package goip

// WrappedAddress is the implementation of ExtendedSegmentSeries for addresses.
type WrappedAddress struct {
	*Address
}

// WrappedAddressSection is the implementation of ExtendedSegmentSeries for address sections.
type WrappedAddressSection struct {
	*AddressSection
}

func wrapAddress(addr *Address) WrappedAddress {
	return WrappedAddress{addr}
}

func wrapSection(section *AddressSection) WrappedAddressSection {
	return WrappedAddressSection{section}
}
