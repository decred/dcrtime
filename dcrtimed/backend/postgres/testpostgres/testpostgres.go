// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpostgres

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/postgres"
	"github.com/decred/dcrtime/merkle"
)

var duration = time.Minute // Default how often we combine digests

// TestPostgres provides a implementation of the backend interface that stores
// records in memory and that can be used for testing.
type TestPostgres struct {
	sync.RWMutex

	myNow    func() time.Time // Override time.Now()
	duration time.Duration    // How often we combine digests

	enableCollections bool // Set to true to enable collection query

	// in memory data
	records map[string]postgres.Record //[hash]Record
	anchors map[string]postgres.Anchor //[merkle]Anchor
}

func (tp *TestPostgres) getRecordsByServerTs(ts int64) (bool, []postgres.Record) {
	rs := []postgres.Record{}

	for _, r := range tp.records {
		if r.CollectionTimestamp == ts {
			rs = append(rs, r)
		}
	}
	return len(rs) > 0, rs
}

func (tp *TestPostgres) getRecordByDigest(hash []byte) (postgres.Record, bool) {
	r, exists := tp.records[hex.EncodeToString(hash)]
	return r, exists
}

func (tp *TestPostgres) insertAnchor(a postgres.Anchor) {
	tp.anchors[hex.EncodeToString(a.Merkle)] = a
}

func (tp *TestPostgres) updateRecordsAnchor(ts int64, merkle []byte) {
	for _, r := range tp.records {
		if r.CollectionTimestamp == ts {
			r.AnchorMerkle = merkle
		}
	}
}

// flush flushes all records associated with given timestamp.
// returns nil iff ts records flushed successfully
//
// This function must be called with the WRITE lock held
func (tp *TestPostgres) flush(ts int64) error {
	// Get timestamp's digests
	_, rs := tp.getRecordsByServerTs(ts)

	if len(rs) == 0 {
		// This really should not happen
	}

	// Convert bytes slices to sha256 arrays
	var digests []*[sha256.Size]byte
	for _, r := range rs {
		var digest [sha256.Size]byte
		copy(digest[:], r.Digest[:])
		digests = append(digests, &digest)
	}

	// Generate merkle
	mt := merkle.Tree(digests)
	// Last element is root
	root := *mt[len(mt)-1]
	a := postgres.Anchor{
		Merkle:         root[:],
		FlushTimestamp: time.Now().Unix(),
	}

	// Insert anchor data into db
	tp.insertAnchor(a)

	// Update timestamp's records merkle root
	tp.updateRecordsAnchor(ts, a.Merkle)

	return nil
}

// GetTimestamps retrieves the digests for a given timestamp.
func (tp *TestPostgres) GetTimestamps(timestamps []int64) ([]backend.TimestampResult, error) {
	gtmes := make([]backend.TimestampResult, 0, len(timestamps))

	tp.RLock()
	defer tp.RUnlock()

	for _, ts := range timestamps {
		gtme := backend.TimestampResult{
			Timestamp: ts,
		}
		if tp.enableCollections {
			exists, records := tp.getRecordsByServerTs(ts)
			if !exists {
				gtme.ErrorCode = backend.ErrorNotFound
			} else {
				gtme.ErrorCode = backend.ErrorOK
				// copy ts digests
				gtme.Digests = make([][sha256.Size]byte, 0, len(records))
				for _, r := range records {
					var d [sha256.Size]byte
					copy(d[:], r.Digest[:])
					gtme.Digests = append(gtme.Digests, d)
					copy(gtme.MerkleRoot[:], r.AnchorMerkle[:])
				}
			}
		} else {
			gtme.ErrorCode = backend.ErrorNotAllowed
		}
		gtmes = append(gtmes, gtme)
	}
	return gtmes, nil
}

// Get returns timestamp information for given digests.
func (tp *TestPostgres) Get(digests [][sha256.Size]byte) ([]backend.GetResult, error) {
	gdmes := make([]backend.GetResult, 0, len(digests))

	tp.RLock()
	defer tp.RUnlock()

	for _, digest := range digests {
		gdme := backend.GetResult{
			Digest: digest,
		}
		r, exists := tp.getRecordByDigest(digest[:])

		if !exists {
			gdme.ErrorCode = backend.ErrorNotFound
		} else {
			gdme.ErrorCode = backend.ErrorOK
			gdme.Timestamp = r.CollectionTimestamp
			copy(gdme.MerkleRoot[:], r.AnchorMerkle[:])
		}
		gdmes = append(gdmes, gdme)
	}

	return gdmes, nil
}

// Put stores hashes and returns timestamp and associated errors.
func (tp *TestPostgres) Put(hashes [][sha256.Size]byte) (int64, []backend.PutResult, error) {
	// Get current time rounded down.
	ts := tp.now().Unix()
	// Prep return
	me := make([]backend.PutResult, 0, len(hashes))

	tp.Lock()
	defer tp.Unlock()

	for _, hash := range hashes {
		d := hex.EncodeToString(hash[:])
		// Check if digest exists
		_, exists := tp.getRecordByDigest(hash[:])
		if exists {
			me = append(me, backend.PutResult{
				Digest:    hash,
				ErrorCode: backend.ErrorExists,
			})
			continue
		}

		dslice, err := hex.DecodeString(d)
		if err != nil {
			return 0, nil, err
		}
		// Add record to map
		tp.records[d] = postgres.Record{
			CollectionTimestamp: ts,
			Digest:              dslice,
		}

		// Mark as successful
		me = append(me, backend.PutResult{
			Digest:    hash,
			ErrorCode: backend.ErrorOK,
		})
	}
	return ts, me, nil
}

// now returns current time stamp rounded down to 1 hour.  All timestamps are
// UTC.
func (tp *TestPostgres) now() time.Time {
	return tp.truncate(tp.myNow().UTC(), tp.duration)
}

// truncate rounds time down to the provided duration.
func (tp *TestPostgres) truncate(t time.Time, d time.Duration) time.Time {
	return t.Truncate(d)
}

// Close is a stub to satisfy the backend interface.
func (tp *TestPostgres) Close() {}

// Dump is a stub to satisfy the backend interface.
func (tp *TestPostgres) Dump(f *os.File, verbose bool) error {
	return nil
}

// Restore is a stub to satisfy the backend interface.
func Restore(f *os.File, verbose bool, location string) error {
	return nil
}

// Fsck is a stub to satisfy the backend interface.
func Fsck(options *backend.FsckOptions) error {
	return nil
}

// GetBalance is a stub to satisfy the backend interface.
func GetBalance() (*backend.GetBalanceResult, error) {
	return nil, nil
}

// LastAnchor is a stub to satisfy the backend interface.
func LastAnchor() (*backend.LastAnchorResult, error) {
	return nil, nil
}

// New returns a new testcache context.
func New() *TestPostgres {
	return &TestPostgres{
		records:  make(map[string]postgres.Record),
		anchors:  make(map[string]postgres.Anchor),
		duration: duration,
		myNow:    time.Now,
	}
}
