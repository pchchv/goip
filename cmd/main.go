package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pchchv/goip"
)

func split(oneStr, twoStr string) []*goip.IPv4Address {
	one := goip.NewIPAddressString(oneStr)
	two := goip.NewIPAddressString(twoStr)
	return one.GetAddress().ToIPv4().SpanWithPrefixBlocksTo(two.GetAddress().ToIPv4())
}

func splitIntoBlocks(one, two string) {
	blocks := split(one, two)
	fmt.Printf("%v from splitting %v and %v: %v\n", len(blocks), one, two, blocks)
}

func splitIntoBlocksSeq(one, two string) {
	blocks := splitSeq(one, two)
	fmt.Printf("%v from splitting %v and %v: %v\n", len(blocks), one, two, blocks)
}

func splitSeq(oneStr, twoStr string) []*goip.IPv4Address {
	one := goip.NewIPAddressString(oneStr)
	two := goip.NewIPAddressString(twoStr)
	return one.GetAddress().ToIPv4().SpanWithSequentialBlocksTo(two.GetAddress().ToIPv4())
}

/*
8 from splitting 0.0.0.0 and 0.0.0.254: [0.0.0.0/25, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
14 from splitting 0.0.0.1 and 0.0.0.254: [0.0.0.1/32, 0.0.0.2/31, 0.0.0.4/30, 0.0.0.8/29, 0.0.0.16/28, 0.0.0.32/27, 0.0.0.64/26, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
8 from splitting 0.0.0.0 and 0.0.0.254: [0.0.0.0/25, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
4 from splitting 0.0.0.10 and 0.0.0.21: [0.0.0.10/31, 0.0.0.12/30, 0.0.0.16/30, 0.0.0.20/31]
1 from splitting 1.2.3.4 and 1.2.3.3-5: [1.2.3.3-5]
4 from splitting 1.2-3.4.5-6 and 2.0.0.0: [1.2.4.5-255, 1.2.5-255.*, 1.3-255.*.*, 2.0.0.0]
2 from splitting 1.2.3.4 and 1.2.4.4: [1.2.3.4-255, 1.2.4.0-4]
2 from splitting 0.0.0.0 and 255.0.0.0: [0-254.*.*.*, 255.0.0.0]
*/

func merge(strs ...string) []*goip.IPAddress {
	first := goip.NewIPAddressString(strs[0]).GetAddress()
	var remaining = make([]*goip.IPAddress, len(strs))
	for i := range strs {
		remaining[i] = goip.NewIPAddressString(strs[i]).GetAddress()
	}
	return first.MergeToPrefixBlocks(remaining...)
}

func NewIPv4AddressTrie() goip.IPv4AddressTrie {
	return goip.IPv4AddressTrie{}
}

func NewAddressTrieNode() goip.TrieNode[*goip.Address] {
	return goip.TrieNode[*goip.Address]{}
}

func zeros() {
	strip := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "goip.", ""),
			"github.com/seancfoley/ipaddress-go/", "")
	}

	typeName := func(i any) string {
		return strip(reflect.ValueOf(i).Elem().Type().Name())
	}

	interfaceTypeName := func(i any) string {
		return strip(reflect.TypeOf(i).String())
	}

	truncateIndent := func(s, indent string) string {
		if boundary := len(indent) - (len(s) >> 3); boundary >= 0 {
			return indent[:boundary] + "\t" // every 8 chars eliminates a tab
		}
		return ""
	}

	baseIndent := "\t\t\t"
	title := "Address item zero values"
	fmt.Printf("%s%sint\tbits\tcount\tstring\n", title, truncateIndent(title, baseIndent))
	vars := []goip.AddressItem{
		&goip.Address{}, &goip.IPAddress{},
		&goip.IPv4Address{}, &goip.IPv6Address{}, &goip.MACAddress{},
		&goip.AddressSection{}, &goip.IPAddressSection{},
		&goip.IPv4AddressSection{}, &goip.IPv6AddressSection{}, &goip.MACAddressSection{},
		&goip.EmbeddedIPv6AddressSection{},
		&goip.AddressDivisionGrouping{}, &goip.IPAddressLargeDivisionGrouping{},
		&goip.IPv6v4MixedAddressGrouping{},
		&goip.AddressSegment{}, &goip.IPAddressSegment{},
		&goip.IPv4AddressSegment{}, &goip.IPv6AddressSegment{}, &goip.MACAddressSegment{},
		&goip.AddressDivision{}, &goip.IPAddressLargeDivision{},
		&goip.IPAddressSeqRange{}, &goip.IPv4AddressSeqRange{}, &goip.IPv6AddressSeqRange{},
	}
	for _, v := range vars {
		name := typeName(v) + "{}"
		indent := truncateIndent(name, baseIndent)
		fmt.Printf("%s%s%v\t%v\t%v\t\"%v\"\n", name, indent, v.GetValue(), v.GetBitCount(), v.GetCount(), v)
	}

	title = "Address item nil pointers"
	fmt.Printf("\n%s%scount\tstring\n", title, truncateIndent(title, baseIndent+"\t\t"))
	nilPtrItems := []goip.AddressItem{
		(*goip.Address)(nil), (*goip.IPAddress)(nil),
		(*goip.IPv4Address)(nil), (*goip.IPv6Address)(nil), (*goip.MACAddress)(nil),

		(*goip.AddressSection)(nil), (*goip.IPAddressSection)(nil),
		(*goip.IPv4AddressSection)(nil), (*goip.IPv6AddressSection)(nil), (*goip.MACAddressSection)(nil),

		(*goip.AddressSegment)(nil), (*goip.IPAddressSegment)(nil),
		(*goip.IPv4AddressSegment)(nil), (*goip.IPv6AddressSegment)(nil), (*goip.MACAddressSegment)(nil),

		(*goip.IPAddressSeqRange)(nil), (*goip.IPv4AddressSeqRange)(nil), (*goip.IPv6AddressSeqRange)(nil),
	}
	for _, v := range nilPtrItems {
		name := "(" + interfaceTypeName(v) + ")(nil)"
		indent := truncateIndent(name, baseIndent+"\t\t")
		fmt.Printf("%s%s%v\t\"%v\"\n", name, indent, v.GetCount(), v)
	}

	title = "Address key zero values"
	fmt.Printf("\n%s%sstring\n", title, truncateIndent(title, baseIndent+"\t\t\t"))
	keys := []fmt.Stringer{
		&goip.AddressKey{}, &goip.IPAddressKey{},
		&goip.IPv4AddressKey{}, &goip.IPv6AddressKey{}, &goip.MACAddressKey{},
		&goip.IPAddressSeqRangeKey{}, &goip.IPv4AddressSeqRangeKey{}, &goip.IPv6AddressSeqRangeKey{},
	}
	for _, k := range keys {
		name := typeName(k) + "{}"
		indent := truncateIndent(name, baseIndent+"\t\t\t")
		fmt.Printf("%s%s\"%v\"\n", name, indent, k)
	}

	title = "Host id zero values"
	fmt.Printf("\n%s%sstring\n", title, truncateIndent(title, baseIndent+"\t\t\t"))
	hostids := []goip.HostIdentifierString{
		&goip.HostName{}, &goip.IPAddressString{}, &goip.MACAddressString{},
	}
	for _, k := range hostids {
		name := typeName(k) + "{}"
		indent := truncateIndent(name, baseIndent+"\t\t\t")
		fmt.Printf("%s%s\"%v\"\n", name, indent, k)
	}

	title = "Host id nil pointers"
	fmt.Printf("\n%s%sstring\n", title, truncateIndent(title, baseIndent+"\t\t\t"))
	nilPtrIds := []goip.HostIdentifierString{
		(*goip.HostName)(nil), (*goip.IPAddressString)(nil), (*goip.MACAddressString)(nil),
	}
	for _, v := range nilPtrIds {
		name := "(" + interfaceTypeName(v) + ")(nil)"
		indent := truncateIndent(name, baseIndent+"\t\t\t")
		fmt.Printf("%s%s\"%v\"\n", name, indent, v)
	}
}
