// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
)

var (
	ErrEmpty = errors.New("empty merkle branch")
)

type sortableSlice []*[sha256.Size]byte

func (s sortableSlice) Len() int      { return len(s) }
func (s sortableSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableSlice) Less(i, j int) bool {
	ii := *s[i]
	jj := *s[j]
	return bytes.Compare(ii[:], jj[:]) < 0
}

// bytes2bits converts merkle tree bitmap into a byte array.
func bytes2bits(b []byte) []byte {
	bits := make([]byte, 0, len(b)*8)
	for i := 0; i < len(b); i++ {
		for j := uint(0); j < 8; j++ {
			bits = append(bits, (b[i]>>j)&0x01)
		}
	}

	return bits
}

// calcTreeWidth calculates the width of the tree at a given height.
// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func calcTreeWidth(num, height uint32) uint32 {
	return (num + (1 << height) - 1) >> height
}

// concatDigests takes a number of sha256 digests and returns the digest of the
// concatenation.
func concatDigests(hashes ...*[sha256.Size]byte) *[sha256.Size]byte {
	h := sha256.New()
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var rv [sha256.Size]byte
	copy(rv[:], h.Sum(nil))
	return &rv
}

// nextPowerOfTwo returns the next highest power of two from a given number if
// it is not already a power of two.  This is a helper function used during the
// calculation of a merkle tree.
func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}
	return 1 << uint64(bits.Len(uint(n)))
}

// Tree creates a merkle tree from a slice of transactions,
// stores it using a linear array, and returns a slice of the backing array.  A
// linear array was chosen as opposed to an actual tree structure since it uses
// about half as much memory.  The following describes a merkle tree and how it
// is stored in a linear array.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes.  A diagram depicting how this works for decred transactions
// where h(x) is a blake256 hash follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The above stored as a linear array is as follows:
//
//	[h1 h2 h3 h4 h12 h34 root]
//
// As the above shows, the merkle root is always the last element in the array.
//
// The number of inputs is not always a power of two which results in a
// balanced tree structure as above.  In that case, parent nodes with no
// children are also zero and parent nodes with only a single left node
// are calculated by concatenating the left node with itself before hashing.
// Since this function uses nodes that are pointers to the hashes, empty nodes
// will be nil.
//
// We always sort the incoming hashes array in order to always generate the
// same merkle tree regardless of input order.
func Tree(hashes []*[sha256.Size]byte) []*[sha256.Size]byte {
	if len(hashes) == 0 {
		return nil
	}

	// Sort hashes.
	sort.Sort(sortableSlice(hashes))

	// Calculate how many entries are required to hold the binary merkle
	// tree as a linear array and create an array of that size.
	nextPoT := nextPowerOfTwo(len(hashes))
	arraySize := nextPoT*2 - 1

	// Create the base transaction hashes and populate the array with them.
	merkles := make([]*[sha256.Size]byte, arraySize)
	copy(merkles, hashes)

	// Start the array offset after the last transaction and adjusted to the
	// next power of two.
	offset := nextPoT
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := concatDigests(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the hash of the
		// concatenation of the left and right children.
		default:
			newHash := concatDigests(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}

	return merkles
}

// Root returns only the merkle root of an array of digests.
func Root(hashes []*[sha256.Size]byte) *[sha256.Size]byte {
	h := Tree(hashes)
	if h == nil {
		return nil
	}
	return h[len(h)-1]
}

// authPath is used to house intermediate information needed to generate a
// Branch.
type authPath struct {
	numLeaves   uint32
	matchedBits []byte
	bits        []byte
	allHashes   []*[sha256.Size]byte
	finalHashes []*[sha256.Size]byte
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (a *authPath) calcHash(height, pos uint32) *[sha256.Size]byte {
	if height == 0 {
		return a.allHashes[pos]
	}

	var right *[sha256.Size]byte
	left := a.calcHash(height-1, pos*2)
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		right = a.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	return concatDigests(left, right)
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.
func (a *authPath) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < a.numLeaves; i++ {
		isParent |= a.matchedBits[i]
	}
	a.bits = append(a.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		a.finalHashes = append(a.finalHashes, a.calcHash(height, pos))
		return
	}

	// Descend into the left child and process its sub-tree.
	a.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		a.traverseAndBuild(height-1, pos*2+1)
	}
}

// Branch is a cooked merkle authentication path that can be transmitted
// over a wire and can be verified on the other end.
type Branch struct {
	NumLeaves uint32              // Nuber of leaves
	Hashes    [][sha256.Size]byte // Merkle branch
	Flags     []byte              // Bitmap of merkle tree
}

// AuthPath returns a Merkle tree authentication path.
func AuthPath(leaves []*[sha256.Size]byte, hash *[sha256.Size]byte) *Branch {
	numLeaves := uint32(len(leaves))
	if numLeaves == 0 {
		return nil
	}
	ap := authPath{
		numLeaves:   numLeaves,
		matchedBits: make([]byte, 0, numLeaves),
		allHashes:   leaves,
	}

	for _, v := range ap.allHashes {
		if v != nil && *v == *hash {
			ap.matchedBits = append(ap.matchedBits, 0x01)
		} else {
			ap.matchedBits = append(ap.matchedBits, 0x00)
		}
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for calcTreeWidth(ap.numLeaves, height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	ap.traverseAndBuild(height, 0)

	// Create merkle branch.
	mb := &Branch{
		NumLeaves: numLeaves,
		Hashes:    make([][sha256.Size]byte, 0, len(ap.finalHashes)),
		Flags:     make([]byte, (len(ap.bits)+7)/8),
	}

	// Create bitmap.
	for i := uint32(0); i < uint32(len(ap.bits)); i++ {
		mb.Flags[i/8] |= ap.bits[i] << (i % 8)
	}

	// Copy hashes
	for _, hash := range ap.finalHashes {
		mb.Hashes = append(mb.Hashes, *hash)
	}

	return mb
}

// merkleBranch holds intermediate state while validating a merkle path.
type merkleBranch struct {
	numLeaves uint32
	bitsUsed  uint32
	hashUsed  uint32
	hashes    [][sha256.Size]byte
	inHashes  [][sha256.Size]byte
	bits      []byte
}

// extract recurses over the merkleBranch and returns the merkle root.
func (m *merkleBranch) extract(height, pos uint32) (*[sha256.Size]byte, error) {
	parentOfMatch := m.bits[m.bitsUsed]
	m.bitsUsed++
	if height == 0 || parentOfMatch == 0 {
		hash := m.inHashes[m.hashUsed]
		m.hashUsed++
		if height == 0 && parentOfMatch == 1 {
			m.hashes = append(m.hashes, hash)
		}
		return &hash, nil
	}

	left, err := m.extract(height-1, pos*2)
	if err != nil {
		return nil, err
	}
	if pos*2+1 < calcTreeWidth(m.numLeaves, height-1) {
		right, err := m.extract(height-1, pos*2+1)
		if err != nil {
			return nil, err
		}
		if *left == *right {
			return nil, fmt.Errorf("equivalent hashes")
		}

		return concatDigests(left, right), nil
	}

	return concatDigests(left, left), nil
}

// VerifyAuthPath takes a Branch and ensures that it is a valid tree.
func VerifyAuthPath(mb *Branch) (*[sha256.Size]byte, error) {
	if mb.NumLeaves == 0 || len(mb.Hashes) == 0 {
		return nil, ErrEmpty
	}

	m := &merkleBranch{
		bits:      bytes2bits(mb.Flags),
		inHashes:  mb.Hashes,
		numLeaves: mb.NumLeaves,
	}

	height := uint32(math.Ceil(math.Log2(float64(mb.NumLeaves))))
	merkleRoot, err := m.extract(height, 0)
	if err != nil {
		return nil, err
	}

	// Validate that we consumed all bits and bobs.
	flagByte := int(math.Floor(float64(m.bitsUsed / 8)))
	if flagByte+1 < len(mb.Flags) && mb.Flags[flagByte] > 1<<m.bitsUsed%8 {
		return nil, fmt.Errorf("did not consume all flag bits")
	}

	if m.hashUsed != uint32(len(mb.Hashes)) {
		return nil, fmt.Errorf("did not consume all hashes")
	}

	return merkleRoot, nil
}
