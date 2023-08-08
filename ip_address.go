package goip

import (
	"math/big"
	"unsafe"
)

// necessary to avoid direct access to IPAddress
type ipAddressInternal struct {
	addressInternal
}

func (addr *ipAddressInternal) toIPAddress() *IPAddress {
	return (*IPAddress)(unsafe.Pointer(addr))
}

// GetPrefixCount returns the count of prefixes in this address or subnet.
//
// The prefix length is given by GetPrefixLen.
//
// If this has a non-nil prefix length, returns the count of the range of values in the prefix.
//
// If this has a nil prefix length, returns the same value as GetCount.
func (addr *ipAddressInternal) GetPrefixCount() *big.Int {
	return addr.addressInternal.GetPrefixCount()
}

// GetPrefixCountLen returns the count of prefixes in this address or subnet for the given prefix length.
//
// If not a subnet of multiple addresses, or a subnet with just single prefix of the given length, returns 1.
func (addr *ipAddressInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	return addr.addressInternal.GetPrefixCountLen(prefixLen)
}
