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
