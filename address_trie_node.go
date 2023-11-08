package goip

import (
	"fmt"
	"unsafe"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/tree"
)

var (
	_ tree.BinTrieNode[trieKey[*Address], any]
	_ tree.BinTrieNode[trieKey[*IPAddress], any]
	_ tree.BinTrieNode[trieKey[*IPv4Address], any]
	_ tree.BinTrieNode[trieKey[*IPv6Address], any]
	_ tree.BinTrieNode[trieKey[*MACAddress], any]
)

// TrieKeyConstraint is the generic type constraint used for tree keys,
// which are individual addresses and prefix block subnets.
type TrieKeyConstraint[T any] interface {
	comparable
	BitItem
	fmt.Stringer
	PrefixedConstraint[T]
	IsOneBit(index BitCount) bool // AddressComponent
	toAddressBase() *Address      // AddressType - used by MatchBits
	getPrefixLen() PrefixLen
	toMaxLower() T
	toMinUpper() T
	trieCompare(other *Address) int
	getTrailingBitCount(ones bool) BitCount
	toSinglePrefixBlockOrAddress() (T, address_error.IncompatibleAddressError)
}

type trieKey[T TrieKeyConstraint[T]] struct {
	address T
}

// ToPrefixBlockLen returns the address key associated with the prefix length provided,
// the address key whose prefix of that length matches the prefix of this address key, and the remaining bits span all values.
//
// The returned address key will represent all addresses with the same prefix as this one, the prefix "block".
func (a trieKey[T]) ToPrefixBlockLen(bitCount BitCount) trieKey[T] {
	addr := a.address.ToPrefixBlockLen(bitCount)
	addr.toAddressBase().assignTrieCache()
	return trieKey[T]{address: addr}
}

func (a trieKey[T]) GetBitCount() tree.BitCount {
	return a.address.GetBitCount()
}

func (a trieKey[T]) String() string {
	return a.address.String()
}

func (a trieKey[T]) IsOneBit(bitIndex tree.BitCount) bool {
	return a.address.IsOneBit(bitIndex)
}

func (a trieKey[T]) GetTrailingBitCount(ones bool) tree.BitCount {
	return a.address.getTrailingBitCount(ones)
}

func (a trieKey[T]) GetPrefixLen() tree.PrefixLen {
	return tree.PrefixLen(a.address.getPrefixLen())
}

// Compare compares to provide the same ordering used by the trie,
// an ordering that works with prefix block subnets and individual addresses.
// The comparator is consistent with the equality of address instances
// and can be used in other contexts.  However, it only works with prefix blocks and individual addresses,
// not with addresses like 1-2.3.4.5-6 which cannot be differentiated using this comparator from 1.3.4.5
// and is thus not consistent with equality for subnets that are not CIDR prefix blocks.
//
// The comparator first compares the prefix of addresses, with the full address value considered the prefix when
// there is no prefix length, ie when it is a single address.  It takes the minimum m of the two prefix lengths and
// compares those m prefix bits in both addresses.  The ordering is determined by which of those two values is smaller or larger.
//
// If both prefix lengths match then both addresses are equal.
// Otherwise it looks at bit m in the address with larger prefix.  If 1 it is larger and if 0 it is smaller than the other.
//
// When comparing an address with a prefix p and an address without, the first p bits in both are compared, and if equal,
// the bit at index p in the non-prefixed address determines the ordering, if 1 it is larger and if 0 it is smaller than the other.
//
// When comparing an address with prefix length matching the bit count to an address with no prefix, they are considered equal if the bits match.
// For instance, 1.2.3.4/32 is equal to 1.2.3.4, and thus the trie does not allow 1.2.3.4/32 in the trie since it is indistinguishable from 1.2.3.4,
// instead 1.2.3.4/32 is converted to 1.2.3.4 when inserted into the trie.
//
// When comparing 0.0.0.0/0, which has no prefix, to other addresses, the first bit in the other address determines the ordering.
// If 1 it is larger and if 0 it is smaller than 0.0.0.0/0.
func (a trieKey[T]) Compare(other trieKey[T]) int {
	return a.address.trieCompare(other.address.toAddressBase())
}

func (a trieKey[T]) GetTrieKeyData() *tree.TrieKeyData {
	return a.address.toAddressBase().getTrieCache()
}

// ToMaxLower changes this key to a new key with a 0 at the first bit beyond the prefix,
// followed by all ones, and with no prefix length.
func (a trieKey[T]) ToMaxLower() trieKey[T] {
	return createKey(a.address.toMaxLower())
}

// ToMinUpper changes this key to a new key with a 1 at the first bit beyond the prefix,
// followed by all zeros, and with no prefix length.
func (a trieKey[T]) ToMinUpper() trieKey[T] {
	return createKey(a.address.toMinUpper())
}

// MatchBits returns false if we need to keep going and try to match sub-nodes.
// MatchBits returns true if the bits do not match, or the bits match to the very end.
func (a trieKey[T]) MatchBits(key trieKey[T], bitIndex int, simpleSearch bool, handleMatch tree.KeyCompareResult, newTrieCache *tree.TrieKeyData) (continueToNext bool, followingBitsFlag uint64) {
	existingAddr := key.address.toAddressBase()

	if simpleSearch {
		// this is the optimized path for the case where we do not need to know how many of the initial bits match in a mismatch
		// when we have a match, all bits match
		// when we have a mismatch, we do not need to know how many of the initial bits match
		// So there is no callback for a mismatch here.

		// The non-optimized code has 8 cases, 2 for each fully nested if or else block
		// I have added comments to see how this code matches up to those 8 cases

		existingTrieCache := existingAddr.getTrieCache()
		if existingTrieCache.Is32Bits {
			if newTrieCache != nil && newTrieCache.Is32Bits {
				existingVal := existingTrieCache.Uint32Val
				existingPrefLen := PrefixLen(existingTrieCache.PrefLen)
				if existingPrefLen == nil {
					newVal := newTrieCache.Uint32Val
					if newVal == existingVal {
						handleMatch.BitsMatch()
					} else {
						newPrefLen := PrefixLen(newTrieCache.PrefLen)
						if newPrefLen != nil {
							newMask := newTrieCache.Mask32Val
							if newVal&newMask == existingVal&newMask {
								// rest of case 1 and rest of case 5
								handleMatch.BitsMatch()
							}
						}
					}
				} else {
					existingPrefLenBits := existingPrefLen.bitCount()
					newPrefLen := PrefixLen(newTrieCache.PrefLen)
					if existingPrefLenBits == 0 {
						if newPrefLen != nil && newPrefLen.bitCount() == 0 {
							handleMatch.BitsMatch()
						} else {
							handleMatch.BitsMatchPartially()
							continueToNext = true
							followingBitsFlag = uint64(newTrieCache.Uint32Val & 0x80000000)
						}
					} else if existingPrefLenBits == bitIndex {
						if newPrefLen != nil && existingPrefLenBits >= newPrefLen.bitCount() {
							handleMatch.BitsMatch()
						} else if handleMatch.BitsMatchPartially() {
							continueToNext = true
							nextBitMask := existingTrieCache.NextBitMask32Val
							followingBitsFlag = uint64(newTrieCache.Uint32Val & nextBitMask)
						}
					} else {
						existingMask := existingTrieCache.Mask32Val
						newVal := newTrieCache.Uint32Val
						if newVal&existingMask == existingVal&existingMask {
							if newPrefLen != nil && existingPrefLenBits >= newPrefLen.bitCount() {
								handleMatch.BitsMatch()
							} else if handleMatch.BitsMatchPartially() {
								continueToNext = true
								nextBitMask := existingTrieCache.NextBitMask32Val
								followingBitsFlag = uint64(newVal & nextBitMask)
							}
						} else if newPrefLen != nil {
							newPrefLenBits := newPrefLen.bitCount()
							if existingPrefLenBits > newPrefLenBits {
								newMask := newTrieCache.Mask32Val
								if newTrieCache.Uint32Val&newMask == existingVal&newMask {
									// rest of case 1 and rest of case 5
									handleMatch.BitsMatch()
								}
							}
						} // else case 4, 7
					}
				}
				return
			}
		} else if existingTrieCache.Is128Bits {
			if newTrieCache != nil && newTrieCache.Is128Bits {
				existingPrefLen := PrefixLen(existingTrieCache.PrefLen)
				if existingPrefLen == nil {
					newLowVal := newTrieCache.Uint64LowVal
					existingLowVal := existingTrieCache.Uint64LowVal
					if newLowVal == existingLowVal &&
						newTrieCache.Uint64HighVal == existingTrieCache.Uint64HighVal {
						handleMatch.BitsMatch()
					} else {
						newPrefLen := PrefixLen(newTrieCache.PrefLen)
						if newPrefLen != nil {
							newMaskLow := newTrieCache.Mask64LowVal
							if newLowVal&newMaskLow == existingLowVal&newMaskLow {
								newMaskHigh := newTrieCache.Mask64HighVal
								if newTrieCache.Uint64HighVal&newMaskHigh == existingTrieCache.Uint64HighVal&newMaskHigh {
									// rest of case 1 and rest of case 5
									handleMatch.BitsMatch()
								}
							}
						} // else case 4, 7
					}
				} else {
					existingPrefLenBits := existingPrefLen.bitCount()
					newPrefLen := PrefixLen(newTrieCache.PrefLen)
					if existingPrefLenBits == 0 {
						if newPrefLen != nil && newPrefLen.bitCount() == 0 {
							handleMatch.BitsMatch()
						} else {
							handleMatch.BitsMatchPartially()
							continueToNext = true
							followingBitsFlag = newTrieCache.Uint64HighVal & 0x8000000000000000
						}
					} else if existingPrefLenBits == bitIndex {
						if newPrefLen != nil && existingPrefLenBits >= newPrefLen.bitCount() {
							handleMatch.BitsMatch()
						} else if handleMatch.BitsMatchPartially() {
							continueToNext = true
							nextBitMask := existingTrieCache.NextBitMask64Val
							if bitIndex > 63 /* IPv6BitCount - 65 */ {
								followingBitsFlag = newTrieCache.Uint64LowVal & nextBitMask
							} else {
								followingBitsFlag = newTrieCache.Uint64HighVal & nextBitMask
							}
						}
					} else if existingPrefLenBits == 64 {
						if newTrieCache.Uint64HighVal == existingTrieCache.Uint64HighVal {
							if newPrefLen != nil && newPrefLen.bitCount() <= 64 {
								handleMatch.BitsMatch()
							} else if handleMatch.BitsMatchPartially() {
								continueToNext = true
								followingBitsFlag = newTrieCache.Uint64LowVal & 0x8000000000000000
							}
						} else {
							if newPrefLen != nil && newPrefLen.bitCount() < 64 {
								newMaskHigh := newTrieCache.Mask64HighVal
								if newTrieCache.Uint64HighVal&newMaskHigh == existingTrieCache.Uint64HighVal&newMaskHigh {
									// rest of case 1 and rest of case 5
									handleMatch.BitsMatch()
								}
							}
						} // else case 4, 7
					} else if existingPrefLenBits > 64 {
						existingMaskLow := existingTrieCache.Mask64LowVal
						newLowVal := newTrieCache.Uint64LowVal
						if newLowVal&existingMaskLow == existingTrieCache.Uint64LowVal&existingMaskLow {
							existingMaskHigh := existingTrieCache.Mask64HighVal
							if newTrieCache.Uint64HighVal&existingMaskHigh == existingTrieCache.Uint64HighVal&existingMaskHigh {
								if newPrefLen != nil && existingPrefLenBits >= newPrefLen.bitCount() {
									handleMatch.BitsMatch()
								} else if handleMatch.BitsMatchPartially() {
									continueToNext = true
									nextBitMask := existingTrieCache.NextBitMask64Val
									followingBitsFlag = newLowVal & nextBitMask
								}
							} else if newPrefLen != nil && existingPrefLenBits > newPrefLen.bitCount() {
								newMaskLow := newTrieCache.Mask64LowVal
								if newTrieCache.Uint64LowVal&newMaskLow == existingTrieCache.Uint64LowVal&newMaskLow {
									newMaskHigh := newTrieCache.Mask64HighVal
									if newTrieCache.Uint64HighVal&newMaskHigh == existingTrieCache.Uint64HighVal&newMaskHigh {
										// rest of case 1 and rest of case 5
										handleMatch.BitsMatch()
									}
								}
							} // else case 4, 7
						} else if newPrefLen != nil && existingPrefLenBits > newPrefLen.bitCount() {
							newMaskLow := newTrieCache.Mask64LowVal
							if newTrieCache.Uint64LowVal&newMaskLow == existingTrieCache.Uint64LowVal&newMaskLow {
								newMaskHigh := newTrieCache.Mask64HighVal
								if newTrieCache.Uint64HighVal&newMaskHigh == existingTrieCache.Uint64HighVal&newMaskHigh {
									// rest of case 1 and rest of case 5
									handleMatch.BitsMatch()
								}
							}
						} // else case 4, 7
					} else { // existingPrefLen.bitCount() < 64
						existingMaskHigh := existingTrieCache.Mask64HighVal
						newHighVal := newTrieCache.Uint64HighVal
						if newHighVal&existingMaskHigh == existingTrieCache.Uint64HighVal&existingMaskHigh {
							if newPrefLen != nil && existingPrefLenBits >= newPrefLen.bitCount() {
								handleMatch.BitsMatch()
							} else if handleMatch.BitsMatchPartially() {
								continueToNext = true
								nextBitMask := existingTrieCache.NextBitMask64Val
								followingBitsFlag = newHighVal & nextBitMask
							}
						} else if newPrefLen != nil && existingPrefLenBits > newPrefLen.bitCount() {
							newMaskHigh := newTrieCache.Mask64HighVal
							if newTrieCache.Uint64HighVal&newMaskHigh == existingTrieCache.Uint64HighVal&newMaskHigh {
								// rest of case 1 and rest of case 5
								handleMatch.BitsMatch()
							}
						} // else case 4, 7
					}
				}
				return
			}
		}
	}

	newAddr := a.address.toAddressBase()
	bitsPerSegment := existingAddr.GetBitsPerSegment()
	bytesPerSegment := existingAddr.GetBytesPerSegment()
	segmentIndex := getHostSegmentIndex(bitIndex, bytesPerSegment, bitsPerSegment)
	segmentCount := existingAddr.GetSegmentCount()
	// the caller already checks total bits, so we only need to check either bitsPerSegment or segmentCount, but not both
	if /* newAddr.GetSegmentCount() != segmentCount || */ bitsPerSegment != newAddr.GetBitsPerSegment() {
		panic("mismatched segment bit length between address trie keys")
	}
	existingPref := existingAddr.GetPrefixLen()
	newPrefLen := newAddr.GetPrefixLen()

	// this block handles cases like matching ::ffff:102:304 to ::ffff:102:304/127,
	// and we found a subnode to match, but we know the final bit is a match due to the subnode being lower or upper,
	// so there is actually not more bits to match
	if segmentIndex >= segmentCount {
		// all the bits match
		handleMatch.BitsMatch()
		return
	}

	bitsMatchedSoFar := getTotalBits(segmentIndex, bytesPerSegment, bitsPerSegment)
	for {
		existingSegment := existingAddr.getSegment(segmentIndex)
		newSegment := newAddr.getSegment(segmentIndex)
		existingSegmentPref := getSegmentPrefLen(existingAddr, existingPref, bitsPerSegment, bitsMatchedSoFar, existingSegment)
		newSegmentPref := getSegmentPrefLen(newAddr, newPrefLen, bitsPerSegment, bitsMatchedSoFar, newSegment)
		if existingSegmentPref != nil {
			existingSegmentPrefLen := existingSegmentPref.bitCount()
			newPrefixLen := newSegmentPref.Len()
			if newSegmentPref != nil && newPrefixLen <= existingSegmentPrefLen {
				matchingBits := getMatchingBits(existingSegment, newSegment, newPrefixLen, bitsPerSegment)
				if matchingBits >= newPrefixLen {
					handleMatch.BitsMatch()
				} else {
					// no match - the bits don't match
					// matchingBits < newPrefLen <= segmentPrefLen
					handleMatch.BitsDoNotMatch(bitsMatchedSoFar + matchingBits)
				}
			} else {
				matchingBits := getMatchingBits(existingSegment, newSegment, existingSegmentPrefLen, bitsPerSegment)
				if matchingBits >= existingSegmentPrefLen { // match - the current subnet/address is a match so far, and we must go further to check smaller subnets
					if handleMatch.BitsMatchPartially() {
						continueToNext = true
						if existingSegmentPrefLen == bitsPerSegment {
							segmentIndex++
							if segmentIndex == segmentCount {
								return
							}
							newSegment = newAddr.getSegment(segmentIndex)
							existingSegmentPrefLen = 0
						}
						if newSegment.IsOneBit(existingSegmentPrefLen) {
							followingBitsFlag = 0x8000000000000000
						}
					}
					return
				}
				// matchingBits < segmentPrefLen - no match - the bits in current prefix do not match the prefix of the existing address
				handleMatch.BitsDoNotMatch(bitsMatchedSoFar + matchingBits)
			}
			return
		} else if newSegmentPref != nil {
			newSegmentPrefLen := newSegmentPref.bitCount()
			matchingBits := getMatchingBits(existingSegment, newSegment, newSegmentPrefLen, bitsPerSegment)
			if matchingBits >= newSegmentPrefLen { // the current bits match the current prefix, but the existing has no prefix
				handleMatch.BitsMatch()
			} else {
				// no match - the current subnet does not match the existing address
				handleMatch.BitsDoNotMatch(bitsMatchedSoFar + matchingBits)
			}
			return
		} else {
			matchingBits := getMatchingBits(existingSegment, newSegment, bitsPerSegment, bitsPerSegment)
			if matchingBits < bitsPerSegment { // no match - the current subnet/address is not here
				handleMatch.BitsDoNotMatch(bitsMatchedSoFar + matchingBits)
				return
			} else {
				segmentIndex++
				if segmentIndex == segmentCount { // match - the current subnet/address is a match
					// note that "added" is already true here, we can only be here if explicitly inserted already since it is a non-prefixed full address
					handleMatch.BitsMatch()
					return
				}
			}
			bitsMatchedSoFar += bitsPerSegment
		}
	}
}

type trieNode[T TrieKeyConstraint[T], V any] struct {
	binNode tree.BinTrieNode[trieKey[T], V]
}

func (node *trieNode[T, V]) toBinTrieNode() *tree.BinTrieNode[trieKey[T], V] {
	return (*tree.BinTrieNode[trieKey[T], V])(unsafe.Pointer(node))
}

// getKey gets the key used for placing the node in the trie.
func (node *trieNode[T, V]) getKey() (t T) {
	return node.toBinTrieNode().GetKey().address
}

func (node *trieNode[T, V]) get(addr T) (V, bool) {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().Get(createKey(addr))
}

func (node *trieNode[T, V]) lowerAddedNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().LowerAddedNode(createKey(addr))
}

func (node *trieNode[T, V]) higherAddedNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().HigherAddedNode(createKey(addr))
}

func (node *trieNode[T, V]) floorAddedNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().FloorAddedNode(createKey(addr))
}

func (node *trieNode[T, V]) ceilingAddedNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().CeilingAddedNode(createKey(addr))
}

// iterator returns an iterator that iterates through
// the elements of the sub-trie with this node as the root.
// The iteration is in sorted element order.
func (node *trieNode[T, V]) iterator() Iterator[T] {
	return addressKeyIterator[T]{node.toBinTrieNode().Iterator()}
}

// descendingIterator returns an iterator that iterates through
// the elements of the subtrie with this node as the root.
// The iteration is in reverse sorted element order.
func (node *trieNode[T, V]) descendingIterator() Iterator[T] {
	return addressKeyIterator[T]{node.toBinTrieNode().DescendingIterator()}
}

// nodeIterator iterates through the added nodes of the sub-trie with this node as the root,
// in forward or reverse tree order.
func (node *trieNode[T, V]) nodeIterator(forward bool) tree.TrieNodeIteratorRem[trieKey[T], V] {
	return node.toBinTrieNode().NodeIterator(forward)
}

// allNodeIterator iterates through all the nodes of the sub-trie with this node as the root,
// in forward or reverse tree order.
func (node *trieNode[T, V]) allNodeIterator(forward bool) tree.TrieNodeIteratorRem[trieKey[T], V] {
	return node.toBinTrieNode().AllNodeIterator(forward)
}

// blockSizeNodeIterator iterates the added nodes,
// ordered by keys from the largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first, otherwise the reverse order is taken.
func (node *trieNode[T, V]) blockSizeNodeIterator(lowerSubNodeFirst bool) tree.TrieNodeIteratorRem[trieKey[T], V] {
	return node.toBinTrieNode().BlockSizeNodeIterator(lowerSubNodeFirst)
}

// blockSizeAllNodeIterator iterates all the nodes,
// ordered by keys from the largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first, otherwise the reverse order
func (node *trieNode[T, V]) blockSizeAllNodeIterator(lowerSubNodeFirst bool) tree.TrieNodeIteratorRem[trieKey[T], V] {
	return node.toBinTrieNode().BlockSizeAllNodeIterator(lowerSubNodeFirst)
}

// blockSizeCachingAllNodeIterator iterates all nodes,
// ordered by keys from the largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
func (node *trieNode[T, V]) blockSizeCachingAllNodeIterator() tree.CachingTrieNodeIterator[trieKey[T], V] {
	return node.toBinTrieNode().BlockSizeCachingAllNodeIterator()
}

func (node *trieNode[T, V]) containingFirstIterator(forwardSubNodeOrder bool) tree.CachingTrieNodeIterator[trieKey[T], V] {
	return node.toBinTrieNode().ContainingFirstIterator(forwardSubNodeOrder)
}

func (node *trieNode[T, V]) containingFirstAllNodeIterator(forwardSubNodeOrder bool) tree.CachingTrieNodeIterator[trieKey[T], V] {
	return node.toBinTrieNode().ContainingFirstAllNodeIterator(forwardSubNodeOrder)
}

func (node *trieNode[T, V]) containedFirstIterator(forwardSubNodeOrder bool) tree.TrieNodeIteratorRem[trieKey[T], V] {
	return node.toBinTrieNode().ContainedFirstIterator(forwardSubNodeOrder)
}

func (node *trieNode[T, V]) containedFirstAllNodeIterator(forwardSubNodeOrder bool) tree.TrieNodeIterator[trieKey[T], V] {
	return node.toBinTrieNode().ContainedFirstAllNodeIterator(forwardSubNodeOrder)
}

func (node *trieNode[T, V]) contains(addr T) bool {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().Contains(createKey(addr))
}

func (node *trieNode[T, V]) removeNode(addr T) bool {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().RemoveNode(createKey(addr))
}

func (node *trieNode[T, V]) removeElementsContainedBy(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().RemoveElementsContainedBy(createKey(addr))
}

func (node *trieNode[T, V]) elementsContainedBy(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().ElementsContainedBy(createKey(addr))
}

func (node *trieNode[T, V]) longestPrefixMatch(addr T) (t T) {
	addr = mustBeBlockOrAddress(addr)
	key, _ := node.toBinTrieNode().LongestPrefixMatch(createKey(addr))
	return key.address
}

func (node *trieNode[T, V]) longestPrefixMatchNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().LongestPrefixMatchNode(createKey(addr))
}

func (node *trieNode[T, V]) elementContains(addr T) bool {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().ElementContains(createKey(addr))
}

func (node *trieNode[T, V]) getNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().GetNode(createKey(addr))
}

func (node *trieNode[T, V]) getAddedNode(addr T) *tree.BinTrieNode[trieKey[T], V] {
	addr = mustBeBlockOrAddress(addr)
	return node.toBinTrieNode().GetAddedNode(createKey(addr))
}

func (node *trieNode[T, V]) elementsContaining(addr T) *containmentPath[T, V] {
	addr = mustBeBlockOrAddress(addr)
	return toContainmentPath[T, V](node.toBinTrieNode().ElementsContaining(createKey(addr)))
}

// ContainmentPath represents a path through the trie of containing subnets,
// each node in the path contained by the previous node,
// the first node corresponding to the shortest prefix match,
// the last element corresponding to the longest prefix match.
type containmentPath[T TrieKeyConstraint[T], V any] struct {
	path tree.Path[trieKey[T], V]
}

// Count returns the count of containing subnets in the path of containing subnets,
// starting from this node and moving downwards to sub-nodes.
// This is a constant-time operation since the size is maintained in
// each node and adjusted with each add and Remove operation in the sub-tree.
func (path *containmentPath[T, V]) count() int {
	if path == nil {
		return 0
	}
	return path.path.Size()
}

// String returns a visual representation of the Path with one node per line.
func (path *containmentPath[T, V]) string() string {
	if path == nil {
		return nilString()
	}
	return path.path.String()
}

// emptyValue changes the way values in strings are printed using EmptyValueType.
type emptyValue = tree.EmptyValueType

// TrieNode is a node in a compact binary prefix trie whose keys
// are prefix block subnets or addresses.
type TrieNode[T TrieKeyConstraint[T]] struct {
	trieNode[T, emptyValue]
}

func (node *TrieNode[T]) toBinTrieNode() *tree.BinTrieNode[trieKey[T], emptyValue] {
	return (*tree.BinTrieNode[trieKey[T], emptyValue])(unsafe.Pointer(node))
}

// tobase is used to convert the pointer rather than doing a field dereference,
// so that nil pointer handling can be done in *addressTrieNode
func (node *TrieNode[T]) tobase() *trieNode[T, emptyValue] {
	return (*trieNode[T, emptyValue])(unsafe.Pointer(node))
}

// GetKey gets the key used to place the node in the trie.
func (node *TrieNode[T]) GetKey() T {
	return node.tobase().getKey()
}

// IsRoot returns whether this node is the root of the trie.
func (node *TrieNode[T]) IsRoot() bool {
	return node.toBinTrieNode().IsRoot()
}

// IsAdded returns whether the node was "added".
// Some binary trie nodes are considered "added" and others are not.
// Those nodes created for key elements added to the trie are "added" nodes.
// Those that are not added are those nodes created to serve as junctions for the added nodes.
// Only added elements contribute to the size of a trie.
// When removing nodes, non-added nodes are removed automatically whenever they are no longer needed,
// which is when an added node has less than two added sub-nodes.
func (node *TrieNode[T]) IsAdded() bool {
	return node.toBinTrieNode().IsAdded()
}

// SetAdded makes this node an added node,
// which is equivalent to adding the corresponding key to the trie.
// If the node is already an added node,
// this method has no effect.
// You cannot set an added node to non-added,
// for that you should Remove the node from the trie by calling Remove.
// A non-added node will only remain in the trie if it needs to be in the trie.
func (node *TrieNode[T]) SetAdded() {
	node.toBinTrieNode().SetAdded()
}

// Clear removes this node and all sub-nodes from the trie,
// after which isEmpty will return true.
func (node *TrieNode[T]) Clear() {
	node.toBinTrieNode().Clear()
}

// IsLeaf returns whether this node is in the trie (a node for which IsAdded is true)
// and there are no elements in the sub-trie with this node as the root.
func (node *TrieNode[T]) IsLeaf() bool {
	return node.toBinTrieNode().IsLeaf()
}

// GetUpperSubNode gets the direct child node whose key is largest in value.
func (node *TrieNode[T]) GetUpperSubNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().GetUpperSubNode())
}

// GetLowerSubNode gets the direct child node whose key is smallest in value.
func (node *TrieNode[T]) GetLowerSubNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().GetLowerSubNode())
}

// GetParent gets the node from which this node is a direct child node, or nil if this is the root.
func (node *TrieNode[T]) GetParent() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().GetParent())
}

// PreviousAddedNode returns the previous node in the trie that is an added node,
// following the trie order in reverse,
// or nil if there is no such node.
func (node *TrieNode[T]) PreviousAddedNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().PreviousAddedNode())
}

// NextAddedNode returns the next node in the trie that is an added node,
// following the trie order,
// or nil if there is no such node.
func (node *TrieNode[T]) NextAddedNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().NextAddedNode())
}

// NextNode returns the node that follows this node following the trie order.
func (node *TrieNode[T]) NextNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().NextNode())
}

// PreviousNode eturns the node that precedes this node following the trie order.
func (node *TrieNode[T]) PreviousNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().PreviousNode())
}

// FirstNode returns the first (the lowest valued) node in the sub-trie originating from this node.
func (node *TrieNode[T]) FirstNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().FirstNode())
}

// FirstAddedNode returns the first (the lowest valued) added node in the sub-trie originating from this node,
// or nil if there are no added entries in this trie or sub-trie.
func (node *TrieNode[T]) FirstAddedNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().FirstAddedNode())
}

// LastNode returns the last (the highest valued) node in the sub-trie originating from this node.
func (node *TrieNode[T]) LastNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().LastNode())
}

// LastAddedNode returns the last (the highest valued) added node in
// the sub-trie originating from this node,
// or nil if there are no added entries in this trie or sub-trie.
func (node *TrieNode[T]) LastAddedNode() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().LastAddedNode())
}

// LowerAddedNode returns the added node,
// in this sub-trie with this node as the root,
// whose address is the highest address strictly less than the given address.
func (node *TrieNode[T]) LowerAddedNode(addr T) *TrieNode[T] {
	return toAddressTrieNode[T](node.tobase().lowerAddedNode(addr))
}

// FloorAddedNode returns the added node,
// in this sub-trie with this node as the root,
// whose address is the highest address less than or equal to the given address.
func (node *TrieNode[T]) FloorAddedNode(addr T) *TrieNode[T] {
	return toAddressTrieNode[T](node.tobase().floorAddedNode(addr))
}

// HigherAddedNode returns the added node,
// in this sub-trie with this node as the root,
// whose address is the lowest address strictly greater than the given address.
func (node *TrieNode[T]) HigherAddedNode(addr T) *TrieNode[T] {
	return toAddressTrieNode[T](node.tobase().higherAddedNode(addr))
}

// CeilingAddedNode returns the added node,
// in this sub-trie with this node as the root,
// whose address is the lowest address greater than or equal to the given address.
func (node *TrieNode[T]) CeilingAddedNode(addr T) *TrieNode[T] {
	return toAddressTrieNode[T](node.tobase().ceilingAddedNode(addr))
}

// Iterator returns an iterator that iterates through
// the elements of the sub-trie with this node as the root.
// The iteration is in sorted element order.
func (node *TrieNode[T]) Iterator() Iterator[T] {
	return node.tobase().iterator()
}

// DescendingIterator returns an iterator that iterates through
// the elements of the subtrie with this node as the root.
// The iteration is in reverse sorted element order.
func (node *TrieNode[T]) DescendingIterator() Iterator[T] {
	return node.tobase().descendingIterator()
}

// NodeIterator returns an iterator that iterates through
// the added nodes of the sub-trie with this node as the root,
// in forward or reverse trie order.
func (node *TrieNode[T]) NodeIterator(forward bool) IteratorWithRemove[*TrieNode[T]] {
	return addressTrieNodeIteratorRem[T, emptyValue]{node.tobase().nodeIterator(forward)}
}

// AllNodeIterator returns an iterator that iterates through all
// the nodes of the sub-trie with this node as the root,
// in forward or reverse trie order.
func (node *TrieNode[T]) AllNodeIterator(forward bool) IteratorWithRemove[*TrieNode[T]] {
	return addressTrieNodeIteratorRem[T, emptyValue]{node.tobase().allNodeIterator(forward)}
}

// BlockSizeNodeIterator returns an iterator that iterates the added nodes,
// ordered by keys from largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first
// , otherwise the reverse order is taken.
func (node *TrieNode[T]) BlockSizeNodeIterator(lowerSubNodeFirst bool) IteratorWithRemove[*TrieNode[T]] {
	return addressTrieNodeIteratorRem[T, emptyValue]{node.tobase().blockSizeNodeIterator(lowerSubNodeFirst)}
}

// BlockSizeAllNodeIterator returns an iterator that iterates all the nodes,
// ordered by keys from largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
//
// If lowerSubNodeFirst is true, for blocks of equal size the lower is first, otherwise the reverse order.
func (node *TrieNode[T]) BlockSizeAllNodeIterator(lowerSubNodeFirst bool) IteratorWithRemove[*TrieNode[T]] {
	return addressTrieNodeIteratorRem[T, emptyValue]{node.tobase().blockSizeAllNodeIterator(lowerSubNodeFirst)}
}

// BlockSizeCachingAllNodeIterator returns an iterator that iterates all nodes, ordered by keys from largest prefix blocks to smallest and then to individual addresses,
// in the sub-trie with this node as the root.
func (node *TrieNode[T]) BlockSizeCachingAllNodeIterator() CachingTrieIterator[*TrieNode[T]] {
	return cachingAddressTrieNodeIterator[T, emptyValue]{node.tobase().blockSizeCachingAllNodeIterator()}
}

// ContainingFirstIterator returns an iterator that does a pre-order binary trie traversal of the added nodes
// of the sub-trie with this node as the root.
//
// All added nodes will be visited before their added sub-nodes.
// For an address trie this means added containing subnet blocks will be visited before their added contained addresses and subnet blocks.
//
// Once a given node is visited, the iterator allows you to cache an object corresponding to the
// lower or upper sub-node that can be retrieved when you later visit that sub-node.
//
// Objects are cached only with nodes to be visited.
// So for this iterator that means an object will be cached with the first added lower or upper sub-node,
// the next lower or upper sub-node to be visited,
// which is not necessarily the direct lower or upper sub-node of a given node.
//
// The caching allows you to provide iteration context from a parent to its sub-nodes when iterating.
// The caching and retrieval is done in constant-time.
func (node *TrieNode[T]) ContainingFirstIterator(forwardSubNodeOrder bool) CachingTrieIterator[*TrieNode[T]] {
	return cachingAddressTrieNodeIterator[T, emptyValue]{node.tobase().containingFirstIterator(forwardSubNodeOrder)}
}

// ContainingFirstAllNodeIterator returns an iterator that does a pre-order binary trie traversal of all the nodes
// of the sub-trie with this node as the root.
//
// All nodes will be visited before their sub-nodes.
// For an address trie this means containing subnet blocks will be visited before their contained addresses and subnet blocks.
//
// Once a given node is visited, the iterator allows you to cache an object corresponding to the
// lower or upper sub-node that can be retrieved when you later visit that sub-node.
// That allows you to provide iteration context from a parent to its sub-nodes when iterating.
// The caching and retrieval is done in constant-time.
func (node *TrieNode[T]) ContainingFirstAllNodeIterator(forwardSubNodeOrder bool) CachingTrieIterator[*TrieNode[T]] {
	return cachingAddressTrieNodeIterator[T, emptyValue]{node.tobase().containingFirstAllNodeIterator(forwardSubNodeOrder)}
}

// ContainedFirstIterator returns an iterator that does a post-order binary trie traversal of the added nodes
// of the sub-trie with this node as the root.
// All added sub-nodes will be visited before their parent nodes.
// For an address trie this means contained addresses and subnets will be visited before their containing subnet blocks.
func (node *TrieNode[T]) ContainedFirstIterator(forwardSubNodeOrder bool) IteratorWithRemove[*TrieNode[T]] {
	return addressTrieNodeIteratorRem[T, emptyValue]{node.tobase().containedFirstIterator(forwardSubNodeOrder)}
}

// ContainedFirstAllNodeIterator returns an iterator that does a post-order binary trie traversal of all the nodes
// of the sub-trie with this node as the root.
// All sub-nodes will be visited before their parent nodes.
// For an address trie this means contained addresses and subnets will be visited before their containing subnet blocks.
func (node *TrieNode[T]) ContainedFirstAllNodeIterator(forwardSubNodeOrder bool) Iterator[*TrieNode[T]] {
	return addressTrieNodeIterator[T, emptyValue]{node.tobase().containedFirstAllNodeIterator(forwardSubNodeOrder)}
}

// Clone clones the node.
// Keys remain the same, but the parent node and the lower and upper sub-nodes are all set to nil.
func (node *TrieNode[T]) Clone() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().Clone())
}

// CloneTree clones the sub-trie starting with this node as the root.
// The nodes are cloned, but their keys and values are not cloned.
func (node *TrieNode[T]) CloneTree() *TrieNode[T] {
	return toAddressTrieNode[T](node.toBinTrieNode().CloneTree())
}

// Compare returns a negative integer, zero, or a positive integer if this node is less than,
// equal, or greater than the other, according to the key and the trie order.
func (node *TrieNode[T]) Compare(other *TrieNode[T]) int {
	return node.toBinTrieNode().Compare(other.toBinTrieNode())
}

// Equal returns whether the address and and mapped value match those of the given node.
func (node *TrieNode[T]) Equal(other *TrieNode[T]) bool {
	return node.toBinTrieNode().Equal(other.toBinTrieNode())
}

// TreeEqual returns whether the sub-tree represented by this node as the root node matches the given sub-trie.
func (node *TrieNode[T]) TreeEqual(other *TrieNode[T]) bool {
	return node.toBinTrieNode().TreeEqual(other.toBinTrieNode())
}

func createKey[T TrieKeyConstraint[T]](addr T) trieKey[T] {
	return trieKey[T]{address: addr}
}

func toContainmentPath[T TrieKeyConstraint[T], V any](path *tree.Path[trieKey[T], V]) *containmentPath[T, V] {
	return (*containmentPath[T, V])(unsafe.Pointer(path))
}

func toAddressTrieNode[T TrieKeyConstraint[T], V any](node *tree.BinTrieNode[trieKey[T], V]) *TrieNode[T] {
	return (*TrieNode[T])(unsafe.Pointer(node))
}
