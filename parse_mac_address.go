package goip

import (
	"sync"

	"github.com/pchchv/goip/address_string_param"
)

type parsedMACAddress struct {
	macAddressParseData
	originator   *MACAddressString
	address      *MACAddress
	params       address_string_param.MACAddressStringParams
	creationLock *sync.Mutex
}

func (provider *parsedMACAddress) getParameters() address_string_param.MACAddressStringParams {
	return provider.params
}

func (parseData *parsedMACAddress) getMACAddressParseData() *macAddressParseData {
	return &parseData.macAddressParseData
}
