package goip

// Iterator iterates collections such as subnets and consecutive address ranges.
type Iterator[T any] interface {
	HasNext() bool // returns true if there is another item to iterate, false otherwise
	Next() T       // returns the next item, or the zero value for T if there is none left
}

// IteratorWithRemove is an iterator that provides a removal operation.
type IteratorWithRemove[T any] interface {
	Iterator[T]
	// Remove removes the last iterated item from the underlying data structure or collection, and returns that element.
	// If there is no such element, it returns the zero value for T.
	Remove() T
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

func (iter *sliceIterator[T]) HasNext() bool {
	return len(iter.elements) > 0
}

func (iter *sliceIterator[T]) Next() (res T) {
	if iter.HasNext() {
		res = iter.elements[0]
		iter.elements = iter.elements[1:]
	}
	return
}

type singleIterator[T any] struct {
	empty    bool
	original T
}

func (it *singleIterator[T]) HasNext() bool {
	return !it.empty
}

func (it *singleIterator[T]) Next() (res T) {
	if it.HasNext() {
		res = it.original
		it.empty = true
	}
	return
}

type multiAddrIterator struct {
	Iterator[*AddressSection]
	zone Zone
}

func (it multiAddrIterator) Next() (res *Address) {
	if it.HasNext() {
		sect := it.Iterator.Next()
		res = createAddress(sect, it.zone)
	}
	return
}

type ipv4AddressIterator struct {
	Iterator[*Address]
}

func (iter ipv4AddressIterator) Next() *IPv4Address {
	return iter.Iterator.Next().ToIPv4()
}

type ipv6AddressIterator struct {
	Iterator[*Address]
}

func (iter ipv6AddressIterator) Next() *IPv6Address {
	return iter.Iterator.Next().ToIPv6()
}

type macAddressIterator struct {
	Iterator[*Address]
}

func (iter macAddressIterator) Next() *MACAddress {
	return iter.Iterator.Next().ToMAC()
}

type addressSeriesIterator struct {
	Iterator[*Address]
}

type ipaddressSeriesIterator struct {
	Iterator[*IPAddress]
}

func nilAddrIterator() Iterator[*Address] {
	return &singleIterator[*Address]{}
}

func nilIterator[T any]() Iterator[T] {
	return &singleIterator[T]{}
}

func addrIterator(single bool, original *Address, prefixLen PrefixLen, valsAreMultiple bool, iterator Iterator[[]*AddressDivision]) Iterator[*Address] {
	if single {
		return &singleIterator[*Address]{original: original}
	}
	return multiAddrIterator{
		Iterator: &multiSectionIterator{
			original:        original.section,
			iterator:        iterator,
			valsAreMultiple: valsAreMultiple,
			prefixLen:       prefixLen,
		},
		zone: original.zone,
	}
}

// rangeAddrIterator used by the sequential ranges
func rangeAddrIterator(single bool, original *Address, prefixLen PrefixLen, valsAreMultiple bool, iterator Iterator[[]*AddressDivision]) Iterator[*Address] {
	return addrIterator(single, original, prefixLen, valsAreMultiple, iterator)
}

func prefixAddrIterator(single bool, original *Address, prefixLen PrefixLen, iterator Iterator[[]*AddressDivision]) Iterator[*Address] {
	var zone Zone

	if single {
		return &singleIterator[*Address]{original: original}
	}

	if original != nil {
		zone = original.zone
	}

	return multiAddrIterator{
		Iterator: &prefixSectionIterator{
			original:  original.section,
			iterator:  iterator,
			prefixLen: prefixLen,
		},
		zone: zone,
	}
}
