package goip

// Iterator iterates collections such as subnets and consecutive address ranges.
type Iterator[T any] interface {
	HasNext() bool // returns true if there is another element to iterate, false otherwise
	Next() T       // returns the next item, or the zero value for T if there is none left
}

type ipAddrIterator struct {
	Iterator[*Address]
}
