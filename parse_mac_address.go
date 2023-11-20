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
