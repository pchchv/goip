package tree

type TrieKeyData struct {
	Is32Bits  bool
	Is128Bits bool
	PrefLen   PrefixLen
	// 32-bit fields
	Uint32Val        uint32
	Mask32Val        uint32
	NextBitMask32Val uint32
	// 128-bit fields
	Uint64HighVal    uint64
	Uint64LowVal     uint64
	Mask64HighVal    uint64
	Mask64LowVal     uint64
	NextBitMask64Val uint64
}

type operation int

// KeyCompareResult has callbacks for a key comparison of a new key with a key pre-existing in the trie.
// At most one of the two methods should be called when comparing keys.
// If existing key is shorter, and the new key matches all bits in the existing key, then neither method should be called.
type KeyCompareResult interface {
	// BitsMatch should be called when the existing key is the same size or large as the new key and the new key bits match the existing key bits.
	BitsMatch()
	// BitsMatchPartially should be called when the existing key is shorter than the new key and the existing key bits match the new key bits.
	// It returns true if further matching is required, which might eventually result in calls to BitsMatch or BitsDoNotMatch.
	BitsMatchPartially() bool
	// BitsDoNotMatch should be called when at least one bit in the new key does not match the same bit in the existing key.
	// You can skip calling it if a prior call to MismatchCallbackRequired returns true.
	BitsDoNotMatch(matchedBits BitCount)
	// MismatchCallbackRequired indicates if you need to call BitsDoNotMatch for a mismatch
	MismatchCallbackRequired() bool
}
