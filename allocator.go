package goip

var (
	_ = PrefixBlockAllocator[*IPAddress]{}
	_ = PrefixBlockAllocator[*IPv4Address]{}
	_ = PrefixBlockAllocator[*IPv6Address]{}
)

// PrefixBlockConstraint is the generic type constraint used for a prefix block allocator.
type PrefixBlockConstraint[T any] interface {
	SequentialRangeConstraint[T]
	MergeToPrefixBlocks(...T) []T
	PrefixBlockIterator() Iterator[T]
}

// PrefixBlockAllocator allocates blocks of the desired size from
// a set of seed blocks provided to it previously for allocation.
//
// The generic type T can be *IPAddress, *IPv4Address or *IPv6Address.
//
// Once a prefix block allocator of generic type *IPAddress has been provided
// with either an IPv4 or IPv6 address or subnet for allocation,
// it can only be used with the same address version from that point onwards.
// In other words, it can allocate either IPv4 or IPv6 blocks, but not both.
//
// The zero value of a PrefixBlockAllocator is an allocator ready for use.
type PrefixBlockAllocator[T PrefixBlockConstraint[T]] struct {
	version         IPVersion
	blocks          [][]T
	reservedCount   int
	totalBlockCount int
}
