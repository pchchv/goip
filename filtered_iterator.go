package goip

type filteredAddrIterator struct {
	skip func(*Address) bool
	iter Iterator[*Address]
	next *Address
}
