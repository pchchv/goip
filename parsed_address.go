package goip

import "github.com/pchchv/goip/address_error"

type sectionResult struct {
	section          *IPAddressSection
	hostSection      *IPAddressSection
	address          *IPAddress
	hostAddress      *IPAddress
	joinHostError    address_error.IncompatibleAddressError
	joinAddressError address_error.IncompatibleAddressError
	mixedError       address_error.IncompatibleAddressError
	maskError        address_error.IncompatibleAddressError
}
