package main

import (
	"flag"

	"github.com/pchchv/goip/test"
)

func main() {
	isLimitedPtr := flag.Bool("limited", false, "exclude caching and threading tests")
	flag.Parse()
	test.Test(*isLimitedPtr)
}
