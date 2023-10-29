package tree

import (
	"math/big"
	"strconv"
)

type Key interface {
	comparable // needed by populateCacheItem
}

var one = bigOne()

type change struct {
	big   *big.Int
	small uint64
}

func (c change) Equal(c2 change) bool {
	if c.small == c2.small {
		if c.big == nil {
			return c2.big == nil
		} else if c2.big != nil {
			return c.big.Cmp(c2.big) == 0
		}
	}
	return false
}

func (c *change) increment() {
	val := c.small
	val++
	if val == 0 {
		if c.big == nil {
			c.big = bigOne()
		} else {
			c.big.Add(c.big, one)
		}
	}
	c.small = val
}

func (c change) String() string {
	return c.big.String() + " " + strconv.FormatUint(c.small, 10)
}

func bigOne() *big.Int {
	return big.NewInt(1)
}
