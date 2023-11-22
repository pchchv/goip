package goip

import (
	"fmt"
	"strings"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

var (
	zeroMACAddressString     = NewMACAddressString("")
	defaultMACAddrParameters = new(address_string_param.MACAddressStringParamsBuilder).ToParams()
)

// MACAddressString parses the string representation of a MAC address.  Such a string can represent just a single address or a collection of addresses like "1:*:1-3:1-4:5:6".
//
// This supports a wide range of address formats and provides specific error messages, and allows specific configuration.
//
// You can control all the supported formats using MACAddressStringParamsBuilder to build a parameters instance of  MACAddressStringParams.
// When not using the constructor that takes a MACAddressStringParams, a default instance of MACAddressStringParams is used that is generally permissive.
//
// # Supported Formats
//
// Ranges are supported:
//
//   - wildcards '*' and ranges '-' (for example "1:*:1-3:1-4:5:6"), useful for working with MAC address collections
//   - SQL wildcards '%" and "_", although '%' is considered an SQL wildcard only when it is not considered an IPv6 zone indicator
//
// The different methods of representing MAC addresses are supported:
//
//   - 6 or 8 bytes in hex representation like "aa:bb:cc:dd:ee:ff"
//   - The same but with a hyphen separator like "aa-bb-cc-dd-ee-ff" (the range separator in this case becomes '/')
//   - The same but with space separator like "aa bb cc dd ee ff"
//   - The dotted representation, 4 sets of 12 bits in hex representation like "aaa.bbb.ccc.ddd"
//   - The 12 or 16 hex representation with no separators like "aabbccddeeff"
//
// All of the above range variations also work for each of these ways of representing MAC addresses.
//
// Some additional formats:
//
//   - null or empty strings representing an unspecified address
//   - the single wildcard address "*" which represents all MAC addresses
//
// Usage
// Once you have constructed a MACAddressString object, you can convert it to a [MACAddress] object with GetAddress or ToAddress.
//
// For empty addresses, both ToAddress and GetAddress return nil.  For invalid addresses, GetAddress and ToAddress return nil, with ToAddress also returning an error.
//
// This type is concurrency-safe.  In fact, MACAddressString objects are immutable.
// A MACAddressString object represents a single MAC address representation that cannot be changed after construction.
// Some derived state is created upon demand and cached, such as the derived [MACAddress] instances.
type MACAddressString struct {
	str             string
	addressProvider macAddressProvider
	validateError   address_error.AddressStringError
}

func (addrStr *MACAddressString) init() *MACAddressString {
	if addrStr.addressProvider == nil && addrStr.validateError == nil {
		return zeroMACAddressString
	}
	return addrStr
}

// String implements the [fmt.Stringer] interface,
// returning the original string used to create this MACAddressString
// (altered by strings.TrimSpace),
// or "<nil>" if the receiver is a nil pointer.
func (addrStr *MACAddressString) String() string {
	if addrStr == nil {
		return nilString()
	}
	return addrStr.str
}

func (addrStr *MACAddressString) validate(validationOptions address_string_param.MACAddressStringParams) {
	addrStr.addressProvider, addrStr.validateError = validator.validateMACAddressStr(addrStr, validationOptions)
}

// Validate validates that this string is a valid address, and if not,
// throws an exception with a descriptive message indicating why it is not.
func (addrStr *MACAddressString) Validate() address_error.AddressStringError {
	return addrStr.init().validateError
}

func (addrStr *MACAddressString) getAddressProvider() (macAddressProvider, address_error.AddressStringError) {
	addrStr = addrStr.init()
	err := addrStr.Validate()
	return addrStr.addressProvider, err
}

// GetValidationOptions returns the validation options supplied when constructing this address string,
// or the default options if no options were supplied.
// It returns nil if no parameters were used to construct the address.
func (addrStr *MACAddressString) GetValidationOptions() address_string_param.MACAddressStringParams {
	provider, _ := addrStr.getAddressProvider()
	if provider != nil {
		return provider.getParameters()
	}
	return nil
}

// Format implements the [fmt.Formatter] interface.
// It accepts the verbs hat are applicable to strings,
// namely the verbs %s, %q, %x and %X.
func (addrStr MACAddressString) Format(state fmt.State, verb rune) {
	s := flagsFromState(state, verb)
	_, _ = state.Write([]byte(fmt.Sprintf(s, addrStr.str)))
}

// ToAddress produces the MACAddress corresponding to this MACAddressString.
//
// If this object does not represent a specific MACAddress or address collection, nil is returned.
//
// If the string used to construct this object is not a known format
// (empty string, address, or range of addresses) then this method returns an error.
//
// An equivalent method that does not return the error is GetAddress.
//
// The error can be address_error.AddressStringError for an invalid string,
// or address_error.IncompatibleAddressError for non-standard strings that cannot be converted to MACAddress.
func (addrStr *MACAddressString) ToAddress() (*MACAddress, address_error.AddressError) {
	provider, err := addrStr.getAddressProvider()
	if err != nil {
		return nil, err
	}
	return provider.getAddress()
}

func parseMACAddressString(str string, params address_string_param.MACAddressStringParams) *MACAddressString {
	str = strings.TrimSpace(str)
	res := &MACAddressString{str: str}
	res.validate(params)
	return res
}

// NewMACAddressString constructs a MACAddressString that will parse
// the given string according to the default parameters.
func NewMACAddressString(str string) *MACAddressString {
	return parseMACAddressString(str, defaultMACAddrParameters)
}

func newMACAddressStringFromAddr(str string, addr *MACAddress) *MACAddressString {
	return &MACAddressString{
		str:             str,
		addressProvider: wrappedMACAddressProvider{addr},
	}
}

// NewMACAddressStringParams constructs a MACAddressString that will parse the given string according to the given parameters.
func NewMACAddressStringParams(str string, params address_string_param.MACAddressStringParams) *MACAddressString {
	var p address_string_param.MACAddressStringParams
	if params == nil {
		p = defaultMACAddrParameters
	} else {
		p = address_string_param.CopyMACAddressStringParams(params)
	}
	return parseMACAddressString(str, p)
}
