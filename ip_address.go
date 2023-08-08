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

// GetBlockCount returns the count of distinct values in the given number of initial (more significant) segments.
func (addr *ipAddressInternal) GetBlockCount(segments int) *big.Int {
	return addr.addressInternal.GetBlockCount(segments)
}

// GetPrefixLen returns the prefix length, or nil if there is no prefix length.
//
// A prefix length indicates the number of bits in the initial part of the address that comprise the prefix.
//
// A prefix is a part of the address that is not specific to that address but common amongst a group of addresses, such as a CIDR prefix block subnet.
//
// For IP addresses, the prefix is explicitly defined when the address is created.
// For example, "1.2.0.0/16" has a prefix length of 16, while "1.2.*.*" has no prefix length,
// even though they both represent the same set of addresses and are considered equal.
// Prefixes can be considered variable for a given IP address and can depend on routing.
//
// The methods GetMinPrefixLenForBlock and GetPrefixLenForSingleBlock can help you
// to obtain or define a prefix length if one does not exist already.
// The method ToPrefixBlockLen allows you to create the subnet consisting of
// the block of addresses for any given prefix length.
func (addr *ipAddressInternal) GetPrefixLen() PrefixLen {
	return addr.addressInternal.GetPrefixLen()
}
