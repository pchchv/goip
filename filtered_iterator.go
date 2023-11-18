package goip

type filteredAddrIterator struct {
	skip func(*Address) bool
	iter Iterator[*Address]
	next *Address
}

func (it *filteredAddrIterator) Next() (res *Address) {
	res = it.next
	for {
		next := it.iter.Next()
		if next == nil || !it.skip(next) {
			it.next = next
			break
		}
	}
	return res
}

func (it *filteredAddrIterator) HasNext() bool {
	return it.next != nil
}
