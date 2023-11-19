package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

type macAddressProvider interface {
	getAddress() (*MACAddress, address_error.IncompatibleAddressError)
	getParameters() address_string_param.MACAddressStringParams // parameters of the address created by parsing
}
