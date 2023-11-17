package goip

import "math/big"

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

// GetBlockCount returns the count of available blocks in this allocator.
func (alloc *PrefixBlockAllocator[T]) GetBlockCount() int {
	return alloc.totalBlockCount
}

// GetVersion returns the IP version of the available blocks in the allocator,
// which is determined by the version of the first block made available to the allocator.
func (alloc *PrefixBlockAllocator[T]) GetVersion() IPVersion {
	return alloc.version
}

// GetTotalCount returns the total of the count of
// all individual addresses available in this allocator,
// which is the total number of individual addresses in all the blocks.
func (alloc *PrefixBlockAllocator[T]) GetTotalCount() *big.Int {
	if alloc.GetBlockCount() == 0 {
		return bigZero()
	}

	result := bigZero()
	version := alloc.version
	for i := len(alloc.blocks) - 1; i >= 0; i-- {
		if blockCount := len(alloc.blocks[i]); blockCount != 0 {
			hostBitCount := HostBitCount(version.GetBitCount() - i)
			size := hostBitCount.BlockSize()
			size.Mul(size, big.NewInt(int64(blockCount)))
			result.Add(result, size)
		}
	}
	return result
}

// SetReserved sets the additional number of addresses to be included in any size allocation.
// Any request for a block of a given size will adjust that size by the given number.
// This can be useful when the size requests do
// not include the count of additional addresses that must be included in every block.
// For IPv4, it is common to reserve two addresses, the network and broadcast addresses.
// If the reservedCount is negative,
// then every request will be shrunk by that number, useful for cases where
// insufficient space requires that all subnets be reduced in size by an equal number.
func (alloc *PrefixBlockAllocator[T]) SetReserved(reservedCount int) {
	alloc.reservedCount = reservedCount
}

// GetReserved returns the reserved count.
// Use SetReserved to change the reserved count.
func (alloc *PrefixBlockAllocator[T]) GetReserved() (reservedCount int) {
	return alloc.reservedCount
}

func (alloc *PrefixBlockAllocator[T]) insertBlocks(blocks []T) {
	for _, block := range blocks {
		prefLen := block.GetPrefixLen().bitCount()
		alloc.blocks[prefLen] = append(alloc.blocks[prefLen], block)
		alloc.totalBlockCount++
	}
}

// GetAvailable returns a list of all
// the blocks available for allocating in the allocator.
func (alloc *PrefixBlockAllocator[T]) GetAvailable() (blocks []T) {
	for _, block := range alloc.blocks {
		blocks = append(blocks, block...)
	}
	return
}
