// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package backend

import (
	"crypto/sha256"
	"errors"
	"os"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/merkle"
)

const (
	ErrorOK         = 0 // Everything's cool
	ErrorExists     = 1 // Digest exists
	ErrorNotFound   = 2 // Generic not found error
	ErrorNotAllowed = 3 // Generic not allowed error
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
	Digest            [sha256.Size]byte // Digest
	ErrorCode         uint              // Error code
	Timestamp         int64             // Server timestamp
	AnchoredTimestamp int64             // Anchored timestamp
	Tx                chainhash.Hash    // Anchor Tx
	MerkleRoot        [sha256.Size]byte // Merkle root
	MerklePath        merkle.Branch     // Auth path
}

// DigestReceived describes when a digest was received by the server.
type DigestReceived struct {
	Digest    string `json:"digest"`    // Digest that was flushed
	Timestamp int64  `json:"timestamp"` // Server received timestamp
}

// FlushRecordJSON is identical to FlushRecord but with corrected JSON
// capitalization. At some point the DB needs to start using this type instead
// of broken one. Timestamp is optional based on the backend.
type FlushRecordJSON struct {
	Root           [sha256.Size]byte    `json:"root"`                // Merkle root
	Hashes         []*[sha256.Size]byte `json:"hashes"`              // All digests
	Tx             chainhash.Hash       `json:"tx"`                  // Tx that anchored merkle tree
	ChainTimestamp int64                `json:"chaintimestamp"`      // Blockchain timestamp, if available
	FlushTimestamp int64                `json:"flushtimestamp"`      // Time flush actually happened
	Timestamp      int64                `json:"timestamp,omitempty"` // Timestamp received
}

// Record types.
const (
	RecordTypeDigestReceived       = "digest"
	RecordTypeDigestReceivedGlobal = "digestglobal"
	RecordTypeFlushRecord          = "flush"

	RecordTypeVersion = 1
)

// RecordType indicates what the next record is in a restore stream. All
// records are dumped prefixed with a RecordType so that they can be simply
// replayed as a journal.
type RecordType struct {
	Version uint   `json:"version"` // Version of RecordType
	Type    string `json:"type"`    // Type or record
}

// FsckOptions provides generic options on how to handle an fsck. Sane defaults
// will be used in lieu of options being provided.
type FsckOptions struct {
	Verbose     bool // Normal verbosity
	PrintHashes bool // Prints every hash
	Fix         bool // Fix fixable errors

	URL  string // URL for dcrdata, used to verify anchors
	File string // Path for results file
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

	// Dump dumps database to the provided file descriptor. If the
	// human flag is set to true it pretty prints the database content
	// otherwise it dumps a JSON stream.
	Dump(*os.File, bool) error

	// Restore recreates the the database from the provided file
	// descriptor. The verbose flag is set to true to indicate that this
	// call may parint to stdout. The provided string describes the target
	// location and is implementation specific.
	Restore(*os.File, bool, string) error

	// Fsck walks all data and verifies its integrity. In addition it
	// verifies anchored timestamps' existence on the blockchain.
	Fsck(*FsckOptions) error
}
