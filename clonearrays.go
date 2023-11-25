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

func cloneToIPSections(orig []ExtendedIPSegmentSeries) []*IPAddressSection {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPAddressSection { return a.(WrappedIPAddressSection).IPAddressSection })
}

func cloneToIPv4Sections(orig []ExtendedIPSegmentSeries) []*IPv4AddressSection {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPv4AddressSection {
		return a.(WrappedIPAddressSection).IPAddressSection.ToIPv4()
	})
}

func cloneToIPv6Sections(orig []ExtendedIPSegmentSeries) []*IPv6AddressSection {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPv6AddressSection {
		return a.(WrappedIPAddressSection).IPAddressSection.ToIPv6()
	})
}

func cloneToIPAddrs(orig []ExtendedIPSegmentSeries) []*IPAddress {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPAddress { return a.(WrappedIPAddress).IPAddress })
}

func cloneToIPv4Addrs(orig []ExtendedIPSegmentSeries) []*IPv4Address {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPv4Address { return a.(WrappedIPAddress).IPAddress.ToIPv4() })
}

func cloneToIPv6Addrs(orig []ExtendedIPSegmentSeries) []*IPv6Address {
	return cloneTo(orig, func(a ExtendedIPSegmentSeries) *IPv6Address { return a.(WrappedIPAddress).IPAddress.ToIPv6() })
}
