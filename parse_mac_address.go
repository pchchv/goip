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

func createRangeSegment(addressString string, lower, upper SegInt, useFlags bool, parseData *addressParseData, parsedSegIndex int, creator parsedAddressCreator) *AddressDivision {
	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(lower, upper, nil)
	} else {
		result = creator.createRangeSegmentInternal(
			lower,
			upper,
			nil,
			addressString,
			lower,
			upper,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getFlag(parsedSegIndex, keyStandardRangeStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex),
			parseData.getIndex(parsedSegIndex, keyUpperStrEndIndex))
	}
	return result
}

func createSegment(addressString string, val, upperVal SegInt, useFlags bool, parseData *addressParseData, parsedSegIndex int, creator parsedAddressCreator) (div *AddressDivision, isMultiple bool) {
	if val != upperVal {
		return createRangeSegment(addressString, val, upperVal, useFlags, parseData, parsedSegIndex, creator), true
	}

	var result *AddressDivision
	if !useFlags {
		result = creator.createSegment(val, val, nil)
	} else {
		result = creator.createSegmentInternal(
			val,
			nil, //prefix length
			addressString,
			val,
			parseData.getFlag(parsedSegIndex, keyStandardStr),
			parseData.getIndex(parsedSegIndex, keyLowerStrStartIndex),
			parseData.getIndex(parsedSegIndex, keyLowerStrEndIndex))
	}
	return result, false
}
