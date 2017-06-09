// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"crypto/sha256"
	"errors"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/merkle"
)

const (
	ErrorOK       = 0 // Everything's cool
	ErrorExists   = 1 // Digest exists
	ErrorNotFound = 2 // Generic not found error
)

var (
	ErrTryAgainLater     = errors.New("busy, try again later")
	ErrTimestampNotFound = errors.New("timestamp not found")
)

// FlushRecord contains blockchain information.  This information only becomes
// available once digests are anchored in the blockchain.  The information
// contained in this record is subject to change due to blockchain realities
// (e.g. a fork).
type FlushRecord struct {
	Root           [sha256.Size]byte    // Merkle root
	Hashes         []*[sha256.Size]byte // All digests
	Tx             chainhash.Hash       // Tx that anchored merkle tree
	ChainTimestamp int64                // Blockchain timestamp, if available
	FlushTimestamp int64                // Time flush actually happened
}

// PutResult is a cooked error returned by the backend.
type PutResult struct {
	Digest    [sha256.Size]byte
	ErrorCode uint
}

// TimestampResult is a cooked error returned by the backend.
type TimestampResult struct {
	Timestamp         int64               // Collection timestamp
	ErrorCode         uint                // Overall result
	AnchoredTimestamp int64               // Anchored timestamp
	Tx                chainhash.Hash      // Anchor Tx
	MerkleRoot        [sha256.Size]byte   // Merkle root
	Digests           [][sha256.Size]byte // All digests
}

// GetResult is a cooked result returned by the backend.
type GetResult struct {
	Digest            [sha256.Size]byte   // Digest
	ErrorCode         uint                // Error code
	Timestamp         int64               // Server timestamp
	AnchoredTimestamp int64               // Anchored timestamp
	Tx                chainhash.Hash      // Anchor Tx
	MerkleRoot        [sha256.Size]byte   // Merkle root
	MerklePath        merkle.MerkleBranch // Auth path
}

type Backend interface {
	// Return timestamp information for given digests.
	Get([][sha256.Size]byte) ([]GetResult, error)

	// Return all hashes for given timestamps.
	GetTimestamps([]int64) ([]TimestampResult, error)

	// Store hashes and return timestamp and associated errors.  Put is
	// allowed to return transient errors.
	Put([][sha256.Size]byte) (int64, []PutResult, error)

	// Close performs cleanup of the backend.
	Close()
}
