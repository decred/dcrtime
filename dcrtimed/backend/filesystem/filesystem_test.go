// Copyright (c) 2017-2026 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/merkle"
)

// newTestFileSystem returns a FileSystem rooted in a temporary directory which
// is automatically removed at the end of each test.
func newTestFileSystem(t *testing.T) *FileSystem {
	t.Helper()

	fs, err := internalNew(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	return fs
}

// makeDigests creates and returns count digests. Each digest is all zeroes
// except for its first byte. The first returned digest will have first byte
// start, the second will have start+1, etc.
func makeDigests(start, count int) [][sha256.Size]byte {
	digests := make([][sha256.Size]byte, 0, count)
	for i := start; i < start+count; i++ {
		digest := [sha256.Size]byte{}
		digest[0] = byte(i)
		digests = append(digests, digest)
	}

	return digests
}

// checkGetResult ensures grs holds all of the digests.
func checkGetResult(t *testing.T, grs []backend.GetResult, digests [][sha256.Size]byte) {
	t.Helper()

	if len(grs) != len(digests) {
		t.Fatalf("expected %v GetResult got %v", len(digests), len(grs))
	}

	for i, gr := range grs {
		if !bytes.Equal(gr.Digest[:], digests[i][:]) {
			t.Fatalf("invalid digest got %x want %x",
				gr.Digest[:], digests[i][:])
		}
	}
}

// checkFoundAndMissing ensures the first count results in grs are the expected
// digests carrying the given error code, and that the remaining results were
// not found.
func checkFoundAndMissing(t *testing.T, grs []backend.GetResult,
	digests [][sha256.Size]byte, count int, errorCode uint) {
	t.Helper()

	if len(grs) != len(digests) {
		t.Fatalf("expected %v GetResult got %v", len(digests), len(grs))
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], digests[i][:]) ||
			gr.ErrorCode != errorCode) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], digests[i][:],
				gr.ErrorCode, errorCode)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}
}

// digestPtrs converts a slice of digests to a slice of pointers to digests.
func digestPtrs(digests [][sha256.Size]byte) []*[sha256.Size]byte {
	ptrs := make([]*[sha256.Size]byte, 0, len(digests))
	for i := range digests {
		ptrs = append(ptrs, &digests[i])
	}

	return ptrs
}

func TestEncodeDecode(t *testing.T) {
	hashes := digestPtrs(makeDigests(0, 10))

	x := [32]byte{0xde, 0xad, 0xbe, 0xef}
	tx, err := chainhash.NewHash(x[:])
	if err != nil {
		t.Fatal(err)
	}
	fr := backend.FlushRecord{
		Root:           *merkle.Root(hashes),
		Hashes:         hashes,
		Tx:             *tx,
		ChainTimestamp: time.Now().Unix(),
		FlushTimestamp: time.Now().Unix(),
	}

	blob, err := EncodeFlushRecord(fr)
	if err != nil {
		t.Fatal(err)
	}

	fr2, err := DecodeFlushRecord(blob)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(fr, *fr2) {
		t.Fatalf("want %v got %v", spew.Sdump(fr), spew.Sdump(*fr2))
	}
}

func TestTimestamp(t *testing.T) {
	fs := FileSystem{duration: time.Hour}

	for i := 0; i < 24; i++ {
		t1, _ := time.Parse("2006 Jan 02 15:04:05",
			fmt.Sprintf("2012 Dec 07 %v:00:01", i))
		t2 := fs.truncate(t1, time.Hour)
		if t1.Sub(t2) != time.Second {
			t.Fatalf("%v -- %v", t1, t2)
		}
	}
}

func TestGetDigests(t *testing.T) {
	fs := newTestFileSystem(t)

	// Override timestampper so that we don't race during test.
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	_, me, err := fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	grs, err := fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkGetResult(t, grs, hashes)

	// Get mixed success and failure
	hashes = append(hashes, makeDigests(count, count)...)

	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkFoundAndMissing(t, grs, hashes, count, foundLocal)

	// Flush and repeat mixed success and failure

	// Flush current container to global database.
	err = fs.flush(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	// Move time forward
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(fs.duration)
	}

	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkFoundAndMissing(t, grs, hashes, count, foundGlobal)

	for _, gr := range grs {
		// Ensure the server timestamp is set to the directory timestamp.
		if gr.ErrorCode == 0 && gr.Timestamp != timestamp {
			t.Fatalf("server timmestamp should be the directory timestamp, want %d got %d",
				timestamp, gr.Timestamp)
		}
		// Ensure the flush timestamp is set
		if gr.ErrorCode == 0 && gr.FlushTimestamp == 0 {
			t.Fatalf("expected flush timestamp to be set, got 0")
		}
	}
}

// TestGetDigestsFoundInPrevious covers the possible digests' codes returned
// from fs.Get(hashes).
//
// Firstly, It puts batch of digests, then it retrieves them using Get func and
// ensures  all digests returned with ErrorCode = foundLocal which means digests
// were found in current container.
// Secondly, it moves time forward, fetchs the digests again and ensures
// all existing returned with ErrorCode = foundPrevious which means digests
// were found in previous container.
func TestGetDigestsFoundInPrevious(t *testing.T) {
	fs := newTestFileSystem(t)

	// Override timestampper so that we don't race during test.
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	_, me, err := fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	grs, err := fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkGetResult(t, grs, hashes)

	// Get mixed success and failure
	hashes = append(hashes, makeDigests(count, count)...)

	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkFoundAndMissing(t, grs, hashes, count, foundLocal)

	// Move time forward.
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(fs.duration)
	}

	// Try again, now we expect count ErrorExists from previous
	// container(foundPrevious).
	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkFoundAndMissing(t, grs, hashes, count, foundPrevious)
}

func TestGetTimestamp(t *testing.T) {
	fs := newTestFileSystem(t)

	// We want to verify collections as well.
	fs.enableCollections = true

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	timestamp, me, err := fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Get invalid timestamp+1, timestamp+2, timestamp+3
	gtmes, err := fs.GetTimestamps([]int64{
		timestamp + 1, timestamp + 2,
		timestamp + 3,
	})
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
	gtmes, err = fs.GetTimestamps([]int64{
		timestamp + 1, timestamp + 2,
		timestamp + 3, timestamp,
	})
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
	gtmes, err = fs.GetTimestamps([]int64{timestamp})
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
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(fs.duration)
	}

	// Flush current container to global database.
	err = fs.flush(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	// Get timestamp again despite not being current
	gtmes, err = fs.GetTimestamps([]int64{timestamp})
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
	// Ensure flush timestamp is set
	if gtme.FlushTimestamp == 0 {
		t.Fatalf("expected flush timestamp to be set, got 0")
	}
}

func TestPut(t *testing.T) {
	fs := newTestFileSystem(t)

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	timestamp, me, err := fs.Put(hashes)
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

	// Try again, now we expect count ErrorExists (foundLocal).
	_, me, err = fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Verify all return codes
	for _, m := range me {
		if m.ErrorCode != foundLocal {
			t.Fatalf("expected ErrorCode %v got %v",
				foundLocal, m.ErrorCode)
		}
	}

	// Override Now() function and move time 1 duration forward.  This
	// causes Put to use the next timestamp container.  We therefore expect
	// collisions to happen on the global database instead.
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(fs.duration)
	}

	// Flush current container to global database.
	err = fs.flush(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	// Try again, now we expect count ErrorExists from global database
	// (foundGlobal).
	_, me, err = fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Verify all return codes
	for _, m := range me {
		if m.ErrorCode != foundGlobal {
			t.Fatalf("expected ErrorCode %v got %v",
				foundGlobal, m.ErrorCode)
		}
	}
}

func TestPutFoundInPrevious(t *testing.T) {
	fs := newTestFileSystem(t)

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	timestamp, me, err := fs.Put(hashes)
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

	// Override Now() function and move time 1 duration forward. This
	// causes Put to use the next timestamp container.
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0).Add(fs.duration)
	}

	// Try again, now we expect count ErrorExists from previous
	// container(foundPrevious).
	timestamp, me, err = fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Verify all return codes
	for _, m := range me {
		if m.ErrorCode != foundPrevious {
			t.Fatalf("expected ErrorCode %v got %v",
				foundPrevious, m.ErrorCode)
		}
	}
}

func TestFlusher(t *testing.T) {
	fs := newTestFileSystem(t)

	// Return our artificial timestamp
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Add bunch of hashes to timestamps.
	buckets := 10
	count := 10
	for i := 0; i < buckets; i++ {
		// Push hashes to database.
		if _, _, err := fs.Put(makeDigests(i*count, count)); err != nil {
			t.Fatal(err)
		}

		// Move time forward by one duration.
		timestamp = time.Unix(timestamp, 0).Add(fs.duration).Unix()
	}

	// Call flusher to flush all unflushed directories.
	flushed, err := fs.doFlush()
	if err != nil {
		t.Fatal(err)
	}
	if flushed != buckets {
		t.Fatalf("unexpected flushed got %v want %d", flushed, buckets)
	}

	// Ensure every dir is flushed by calling flusher one more time and
	// expect a 0 return.
	flushed, err = fs.doFlush()
	if err != nil {
		t.Fatal(err)
	}
	if flushed != 0 {
		t.Fatalf("unexpected flushed got %v want 0", flushed)
	}

	// Read back expected hashes from global database.
	var hashes [][sha256.Size]byte
	for i := 0; i < buckets; i++ {
		hashes = append(hashes, makeDigests(i*count, count)...)
	}

	grs, err := fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	checkGetResult(t, grs, hashes)
}

func TestFlusherSkipNow(t *testing.T) {
	fs := newTestFileSystem(t)

	// Put batch success in current time
	count := 10
	hashes := makeDigests(0, count)

	timestamp, me, err := fs.Put(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(me) != count {
		t.Fatalf("expected %v multi error", count)
	}

	// Expect a 0 return because we skip current timestamp.
	flushed, err := fs.doFlush()
	if err != nil {
		t.Fatal(err)
	}
	if flushed != 0 {
		t.Fatalf("unexpected flushed got %v want 0", flushed)
	}

	// Check using isFlushed as well.
	if fs.isFlushed(timestamp) {
		t.Fatalf("unexpected now to not be flushed")
	}
}

// TestLastDigests flushes a batch of digests to the filesystem, fetches them
// with LastDigests, and then ensures the merkle root and path returned for each
// digest is correct.
func TestLastDigests(t *testing.T) {
	fs := newTestFileSystem(t)

	fs.enableCollections = true
	fs.maxDigests = 100

	// Return our artificial timestamp
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Timestamp a collection of distinct digests and flush it so that the
	// collection has a merkle root.
	count := 10
	hashes := makeDigests(0, count)
	if _, _, err := fs.Put(hashes); err != nil {
		t.Fatal(err)
	}

	// Move time forward by one duration and flush.
	timestamp = time.Unix(timestamp, 0).Add(fs.duration).Unix()
	flushed, err := fs.doFlush()
	if err != nil {
		t.Fatal(err)
	}
	if flushed != 1 {
		t.Fatalf("unexpected flushed got %v want 1", flushed)
	}

	grs, err := fs.LastDigests(int32(count))
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count {
		t.Fatalf("expected %v GetResult got %v", count, len(grs))
	}

	leaves := digestPtrs(hashes)
	root := *merkle.Root(leaves)

	for i := range grs {
		gr := grs[i]
		// Validate the merkle root.
		if gr.MerkleRoot != root {
			t.Fatalf("invalid merkle root got %x want %x", gr.MerkleRoot, root)
		}

		// Validate the auth path.
		want := merkle.AuthPath(leaves, &gr.Digest)
		if !reflect.DeepEqual(gr.MerklePath, *want) {
			t.Fatalf("digest %x: incorrect auth path got %s want %s",
				gr.Digest, spew.Sdump(gr.MerklePath), spew.Sdump(*want))
		}
	}
}
