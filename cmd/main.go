package main

import (
	"fmt"

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
