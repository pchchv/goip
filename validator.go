package goip

import (
	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

const (
	SmtpIPv6Identifier = "IPv6:"
	IPvFuture          = 'v'
)

var _ hostIdentifierStringValidator = strValidator{}

// Interface for validation and parsing of host identifier strings
type hostIdentifierStringValidator interface {
	validateHostName(fromHost *HostName, validationOptions address_string_param.HostNameParams) (*parsedHost, address_error.HostNameError)
	validateIPAddressStr(fromString *IPAddressString, validationOptions address_string_param.IPAddressStringParams) (ipAddressProvider, address_error.AddressStringError)
	validateMACAddressStr(fromString *MACAddressString, validationOptions address_string_param.MACAddressStringParams) (macAddressProvider, address_error.AddressStringError)
	validatePrefixLenStr(fullAddr string, version IPVersion) (PrefixLen, address_error.AddressStringError)
}
