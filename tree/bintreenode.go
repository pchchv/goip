package tree

import "math/big"

type Key interface {
	comparable // needed by populateCacheItem
}

type change struct {
	big   *big.Int
	small uint64
}

func bigOne() *big.Int {
	return big.NewInt(1)
}
