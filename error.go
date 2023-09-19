package goip

import (
	"strconv"

	"github.com/pchchv/goip/address_error"
)

type addressError struct {
	key string // to look up the error message
	str string // an optional string with the address
}

func (a *addressError) Error() string {
	return getStr(a.str) + lookupStr("goip.address.error") + " " + lookupStr(a.key)
}

// GetKey can be used to internationalize error strings in the goip library.
// The list of keys and their English translations are listed in the goipResources.properties file.
// Use your own method to map keys to your translations.
// One such method is golang.org/x/text, which provides language tags
// (https://pkg.go.dev/golang.org/x/text/language?utm_source=godoc#Tag)
// that can then be mapped to catalogs, each catalog being a translation list for the set of keys presented here.
// In the code, you specify the language key to use the right catalog.
// You can use the gotext tool to integrate these translations into your application.
func (a *addressError) GetKey() string {
	return a.key
}

func getStr(str string) (res string) {
	if len(str) > 0 {
		res = str + " "
	}
	return
}

type incompatibleAddressError struct {
	addressError
}

type sizeMismatchError struct {
	incompatibleAddressError
}

type addressValueError struct {
	addressError
	val int
}

type mergedError struct {
	address_error.AddressError
	merged []address_error.AddressError
}

func (a *mergedError) GetMerged() []address_error.AddressError {
	return a.merged
}

type addressStringError struct {
	addressError
}

type addressStringNestedError struct {
	addressStringError
	nested address_error.AddressStringError
}

func (a *addressStringNestedError) Error() string {
	return a.addressError.Error() + ": " + a.nested.Error()
}

type addressStringIndexError struct {
	addressStringError
	index int // byte index location in string of the error
}

func (a *addressStringIndexError) Error() string {
	return lookupStr("goip.address.error") + " " + lookupStr(a.key) + " " + strconv.Itoa(a.index)
}

type hostNameError struct {
	addressError
}

// GetAddress_Erroror returns the nested address error which is nil for a host name error
func (a *hostNameError) GetAddress_Erroror() address_error.AddressError {
	return nil
}

func (a *hostNameError) Error() string {
	return getStr(a.str) + lookupStr("goip.host.error") + " " + lookupStr(a.key)
}

type hostNameNestedError struct {
	hostNameError
	nested error
}

type hostNameIndexError struct {
	hostNameError
	index int
}

func (a *hostNameIndexError) Error() string {
	return getStr(a.str) + lookupStr("goip.host.error") + " " + lookupStr(a.key) + " " + strconv.Itoa(a.index)
}
