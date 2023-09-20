package goip

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

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

type hostAddressNestedError struct {
	hostNameIndexError
	nested address_error.AddressError
}

// GetAddress_Erroror returns the nested address error
func (a *hostAddressNestedError) GetAddress_Erroror() address_error.AddressError {
	return a.nested
}

func (a *hostAddressNestedError) Error() string {
	if a.hostNameIndexError.key != "" {
		return getStr(a.str) + lookupStr("goip.host.error") + " " + a.hostNameIndexError.Error() + " " + a.nested.Error()
	}
	return getStr(a.str) + lookupStr("goip.host.error") + " " + a.nested.Error()
}

type wrappedErr struct {
	cause error // root cause
	err   error // wrapper
	str   string
}

func (wrappedErr *wrappedErr) Error() string {
	str := wrappedErr.str
	if len(str) > 0 {
		return str
	}

	str = wrappedErr.err.Error() + ": " + wrappedErr.cause.Error()
	wrappedErr.str = str

	return str
}

type mergedErr struct {
	mergedErrs []error
	str        string
}

func (merged *mergedErr) Error() (str string) {
	str = merged.str
	if len(str) > 0 {
		return
	}

	mergedErrs := merged.mergedErrs
	errLen := len(mergedErrs)
	strs := make([]string, errLen)
	totalLen := 0

	for i, err := range mergedErrs {
		str := err.Error()
		strs[i] = str
		totalLen += len(str)
	}

	format := strings.Builder{}
	format.Grow(totalLen + errLen*2)
	format.WriteString(strs[0])

	for _, str := range strs[1:] {
		format.WriteString(", ")
		format.WriteString(str)
	}

	str = format.String()
	merged.str = str
	return
}

func newError(str string) error {
	return errors.New(str)
}

// errorF returns a formatted error
func errorF(format string, a ...interface{}) error {
	return errors.New(fmt.Sprintf(format, a...))
}

func wrapper(nilIfFirstNil bool, err error, format string, a ...interface{}) error {
	if err == nil {
		if nilIfFirstNil {
			return nil
		}
		return errorF(format, a...)
	}
	return &wrappedErr{
		cause: err,
		err:   errorF(format, a...),
	}
}

// wrapErrf wraps the given error, but only if it is not nil.
func wrapErrf(err error, format string, a ...interface{}) error {
	return wrapper(true, err, format, a...)
}

// wrapToErrf is like wrapErrf but always returns an error
func wrapToErrf(err error, format string, a ...interface{}) error {
	return wrapper(false, err, format, a...)
}

// mergeErrs merges an existing error with a new one
func mergeErrs(err error, format string, a ...interface{}) error {
	newErr := errorF(format, a...)

	if err == nil {
		return newErr
	}

	var merged []error

	if merge, isMergedErr := err.(*mergedErr); isMergedErr {
		merged = append(append([]error(nil), merge.mergedErrs...), newErr)
	} else {
		merged = []error{err, newErr}
	}

	return &mergedErr{mergedErrs: merged}
}

// mergeErrors merges multiple errors
func mergeAllErrs(errs ...error) error {
	var all []error
	allLen := len(errs)
	if allLen <= 1 {
		if allLen == 0 {
			return nil
		}
		return errs[0]
	}

	for _, err := range errs {
		if err != nil {
			if merge, isMergedErr := err.(*mergedErr); isMergedErr {
				all = append(all, merge.mergedErrs...)
			} else {
				all = append(all, err)
			}
		}
	}

	allLen = len(all)
	if allLen <= 1 {
		if allLen == 0 {
			return nil
		}
		return all[0]
	}

	return &mergedErr{mergedErrs: all}
}
