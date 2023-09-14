package goip

// Iterator iterates collections such as subnets and consecutive address ranges.
type Iterator[T any] interface {
	HasNext() bool // returns true if there is another element to iterate, false otherwise
	Next() T       // returns the next item, or the zero value for T if there is none left
}

type ipAddrIterator struct {
	Iterator[*Address]
}

func (iter ipAddrIterator) Next() *IPAddress {
	return iter.Iterator.Next().ToIP()
}

type sliceIterator[T any] struct {
	elements []T
}
