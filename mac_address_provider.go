package goip

import (
	"sync"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

var macAddressDefaultAllProvider = &macAddressAllProvider{validationOptions: defaultMACAddrParameters, creationLock: &sync.Mutex{}}

type macAddressProvider interface {
	getAddress() (*MACAddress, address_error.IncompatibleAddressError)
	getParameters() address_string_param.MACAddressStringParams // parameters of the address created by parsing
}

type macAddressNullProvider struct {
	validationOptions address_string_param.MACAddressStringParams
}

func (provider macAddressNullProvider) getParameters() address_string_param.MACAddressStringParams {
	return provider.validationOptions
}

func (provider macAddressNullProvider) getAddress() (*MACAddress, address_error.IncompatibleAddressError) {
	return nil, nil
}

type macAddressAllProvider struct {
	validationOptions address_string_param.MACAddressStringParams
	address           *MACAddress
	creationLock      *sync.Mutex
}

func (provider *macAddressAllProvider) getParameters() address_string_param.MACAddressStringParams {
	return provider.validationOptions
}

func (provider *macAddressAllProvider) getAddress() (*MACAddress, address_error.IncompatibleAddressError) {
	addr := provider.address
	if addr == nil {
		provider.creationLock.Lock()
		addr = provider.address
		if addr == nil {
			validationOptions := provider.validationOptions
			size := validationOptions.GetPreferredLen()
			creator := macType.getNetwork().getAddressCreator()
			var segCount int
			if size == address_string_param.EUI64Len {
				segCount = ExtendedUniqueIdentifier64SegmentCount
			} else {
				segCount = MediaAccessControlSegmentCount
			}
			allRangeSegment := creator.createRangeSegment(0, MACMaxValuePerSegment)
			segments := make([]*AddressDivision, segCount)
			for i := range segments {
				segments[i] = allRangeSegment
			}
			section := creator.createSectionInternal(segments, true)
			addr = creator.createAddressInternal(section.ToSectionBase(), nil).ToMAC()
		}
		provider.creationLock.Unlock()
	}
	return addr, nil
}
