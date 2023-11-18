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

type filteredIPAddrIterator struct {
	skip func(*IPAddress) bool
	iter Iterator[*IPAddress]
	next *IPAddress
}

func (it *filteredIPAddrIterator) Next() (res *IPAddress) {
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

func (it *filteredIPAddrIterator) HasNext() bool {
	return it.next != nil
}

// NewFilteredIPAddrIterator returns an iterator similar to the passed in iterator,
// but skipping those elements for which the "skip" function returns true
func NewFilteredIPAddrIterator(iter Iterator[*IPAddress], skip func(*IPAddress) bool) Iterator[*IPAddress] {
	res := &filteredIPAddrIterator{skip: skip, iter: iter}
	res.Next()
	return res
}

// NewFilteredAddrIterator modifies an address iterator to skip certain addresses,
// skipping those elements for which the "skip" function returns true
func NewFilteredAddrIterator(iter Iterator[*Address], skip func(*Address) bool) Iterator[*Address] {
	res := &filteredAddrIterator{skip: skip, iter: iter}
	res.Next()
	return res
}
