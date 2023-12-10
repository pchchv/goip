package test

import "math/big"

func setBigString(str string, base int) *big.Int {
	res, b := new(big.Int).SetString(str, base)
	if !b {
		panic("bad string for big int")
	}
	return res
}
