// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import "github.com/decred/dcrtime/merkle"

// Record records collected digests, it includes the collection timestamp
// and the anchor merkle root if the digest was anchored
type Record struct {
	Digest              []byte
	CollectionTimestamp int64
	AnchorMerkle        []byte
}

// Anchor records anchors information, it includes the merkle root of all
// digests included in a given anchor, the anchor's transaction hash, the flush
// timestamp and the chain timestamp if the transaction has enough
// confirmations.
type Anchor struct {
	Merkle         []byte
	TxHash         []byte
	ChainTimestamp int64
	FlushTimestamp int64
}

// AnchoredRecord is a wrapper struct, used to return record's and it's
// corresponding anchor information if digest was anchored.
type AnchoredRecord struct {
	Record Record
	Anchor Anchor
	// Not stored on db, calculated and returned to client for verification
	MerklePath merkle.Branch
}
