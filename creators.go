package goip

type addressSegmentCreator interface {
	createRangeSegment(lower, upper SegInt) *AddressDivision
	createSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	createSegmentInternal(
		value SegInt,
		segmentPrefixLength PrefixLen,
		addressStr string,
		originalVal SegInt,
		isStandardString bool,
		lowerStringStartIndex,
		lowerStringEndIndex int) *AddressDivision
	createRangeSegmentInternal(lower, upper SegInt, segmentPrefixLength PrefixLen, addressStr string,
		originalLower, originalUpper SegInt, isStandardString, isStandardRangeString bool,
		lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex int) *AddressDivision
	createPrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *AddressDivision
	getMaxValuePerSegment() SegInt
}

type parsedAddressCreator interface {
	addressSegmentCreator
	createSectionInternal(segments []*AddressDivision, isMultiple bool) *AddressSection
	createAddressInternal(section *AddressSection, identifier HostIdentifierString) *Address
}

type parsedIPAddressCreator interface {
	createPrefixedSectionInternalSingle(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection
	createPrefixedSectionInternal(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection
	createAddressInternalFromSection(*IPAddressSection, Zone, HostIdentifierString) *IPAddress
}

type ipAddressCreator interface {
	parsedAddressCreator
	parsedIPAddressCreator
	createAddressInternalFromBytes(bytes []byte, zone Zone) *IPAddress
}

type ipv6AddressCreator struct{}

func (creator *ipv6AddressCreator) getMaxValuePerSegment() SegInt {
	return IPv6MaxValuePerSegment
}

func (creator *ipv6AddressCreator) createPrefixedSectionInternal(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection {
	return newPrefixedIPv6SectionParsed(segments, isMultiple, prefixLength, false).ToIP()
}

func (creator *ipv6AddressCreator) createPrefixedSectionInternalSingle(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen) *IPAddressSection {
	return newPrefixedIPv6SectionParsed(segments, isMultiple, prefixLength, true).ToIP()
}
