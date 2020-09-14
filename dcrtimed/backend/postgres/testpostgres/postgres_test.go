// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpostgres

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
)

func TestGetTimestamp(t *testing.T) {
	tp := New()

	// we want to verify collections as well
	tp.enableCollections = true

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}
	timestamp, me, err := tp.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Get invalid timestamp+1, timestamp+2, timestamp+3
	gtmes, err := tp.GetTimestamps([]int64{timestamp + 1, timestamp + 2,
		timestamp + 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(gtmes) != 3 {
		t.Fatalf("expected 3 gtmes got %v", len(gtmes))
	}
	for _, gtme := range gtmes {
		if gtme.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("expected ErrorNotFound got %v",
				gtme.ErrorCode)
		}
	}

	// Get invalid timestamp+1, timestamp+2, timestamp+3 and valid timestamp
	gtmes, err = tp.GetTimestamps([]int64{timestamp + 1, timestamp + 2,
		timestamp + 3, timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if len(gtmes) != 4 {
		t.Fatalf("expected 4 gtmes got %v", len(gtmes))
	}
	for i, gtme := range gtmes {
		if i < len(gtmes)-1 && gtme.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("expected ErrorNotFound got %v",
				gtme.ErrorCode)
		}
		if i == len(gtmes)-1 && gtme.ErrorCode != backend.ErrorOK {
			t.Fatalf("expected ErrorOK got %v", gtme.ErrorCode)
		}
	}

	// Get with timestamp
	gtmes, err = tp.GetTimestamps([]int64{timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if len(gtmes) != 1 {
		t.Fatalf("expected 1 gtmes got %v", len(gtmes))
	}
	gtme := gtmes[0]
	// Verify we got all the bits back.
	if len(gtme.Digests) != count {
		t.Fatalf("expected %v digests got %v", count, len(gtme.Digests))
	}
	exists := make(map[byte]struct{})
	for _, digest := range gtme.Digests {
		if _, ok := exists[digest[0]]; ok {
			t.Fatalf("dup %v", digest[0])
		}
		exists[digest[0]] = struct{}{}
	}
	if len(exists) != count {
		t.Fatalf("expected %v exists got %v", count, len(exists))
	}

	// Move time forward and flush
	tp.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(tp.duration)
	}

	// Flush current container to global database.
	err = tp.flush(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	// Get timestamp again despite not being current
	gtmes, err = tp.GetTimestamps([]int64{timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if len(gtmes) != 1 {
		t.Fatalf("expected 1 gtmes got %v", len(gtmes))
	}
	gtme = gtmes[0]

	// Verify we got all the bits back.
	if len(gtme.Digests) != count {
		t.Fatalf("expected %v digests got %v", count, len(gtme.Digests))
	}
	if bytes.Equal(gtme.MerkleRoot[:], []byte{}) {
		t.Fatalf("expected non empty merkle root got %x", gtme.MerkleRoot)
	}
	exists = make(map[byte]struct{})
	for _, digest := range gtme.Digests {
		if _, ok := exists[digest[0]]; ok {
			t.Fatalf("dup %v", digest[0])
		}
		exists[digest[0]] = struct{}{}
	}
	if len(exists) != count {
		t.Fatalf("expected %v exists got %v", count, len(exists))
	}
}

func TestGetDigests(t *testing.T) {
	tp := New()

	timestamp := tp.now().Unix()
	tp.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

	_, me, err := tp.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	grs, err := tp.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count {
		t.Fatalf("expected %v GetResult, got %v", count, len(grs))
	}

	for i, gr := range grs {
		if !bytes.Equal(gr.Digest[:], hashes[i][:]) {
			t.Fatalf("invalid digest got %x want %x",
				gr.Digest[:], hashes[i][:])
		}
	}

	// Get mixed success and failure
	for i := count; i < count*2; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

	grs, err = tp.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			gr.ErrorCode != backend.ErrorOK) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], hashes[i][:],
				gr.ErrorCode, backend.ErrorOK)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}

	// Flush and repeat mixed success and failure

	// Flush current container
	err = tp.flush(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	grs, err = tp.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	// Validate returned merkle root
	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			bytes.Equal(gr.MerkleRoot[:], []byte{})) {
			t.Fatalf("invalid digest got %x want %x Merkle %x", gr.Digest[:],
				hashes[i][:], gr.MerkleRoot[:])
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}
}

func TestPut(t *testing.T) {
	tp := New()

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

	_, me, err := tp.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Verify all return codes
	for _, m := range me {
		if m.ErrorCode != backend.ErrorOK {
			t.Fatalf("expected ErrorCode %v got %v",
				backend.ErrorOK, m.ErrorCode)
		}
	}

	// Try again, now we expect count ErrorExists.
	_, me, err = tp.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Verify all return codes
	for _, m := range me {
		if m.ErrorCode != backend.ErrorExists {
			t.Fatalf("expected ErrorCode %v got %v",
				backend.ErrorExists, m.ErrorCode)
		}
	}
}
