// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/merkle"
)

func TestEncodeDecode(t *testing.T) {
	var hashes []*[sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, &hash)
	}

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
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Override timestampper so that we don't race during test.
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
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
	if len(grs) != count {
		t.Fatalf("expected %v GetResult", count)
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

	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			gr.ErrorCode != foundLocal) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], hashes[i][:],
				gr.ErrorCode, foundLocal)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}

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
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			gr.ErrorCode != foundGlobal) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], hashes[i][:],
				gr.ErrorCode, foundGlobal)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
		// Ensure the server timestamp is set to the directory timestamp.
		if gr.ErrorCode == 0 && gr.Timestamp != timestamp {
			t.Fatalf("server timmestamp should be the directory timestamp, want %d got %d",
				timestamp, gr.Timestamp)
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
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Override timestampper so that we don't race during test.
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
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
	if len(grs) != count {
		t.Fatalf("expected %v GetResult", count)
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

	grs, err = fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			gr.ErrorCode != foundLocal) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], hashes[i][:],
				gr.ErrorCode, foundLocal)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}

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
	if len(grs) != count*2 {
		t.Fatalf("expected %v GetResult", count*2)
	}

	for i, gr := range grs {
		if i < count-1 && (!bytes.Equal(gr.Digest[:], hashes[i][:]) ||
			gr.ErrorCode != foundPrevious) {
			t.Fatalf("invalid digest got %x want %x ErrorCode "+
				"got %v want %v", gr.Digest[:], hashes[i][:],
				gr.ErrorCode, foundPrevious)
		}
		if i >= count && gr.ErrorCode != backend.ErrorNotFound {
			t.Fatalf("invalid ErrorCode got %x want %x",
				gr.ErrorCode, backend.ErrorNotFound)
		}
	}
}

func TestGetTimestamp(t *testing.T) {
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// We want to verify collections as well.
	fs.enableCollections = true

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

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
}

func TestPut(t *testing.T) {
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

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
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

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
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Return our artificial timestamp
	timestamp := fs.now().Unix()
	fs.myNow = func() time.Time {
		return time.Unix(timestamp, 0)
	}

	// Add bunch of hashes to timestamps.
	buckets := 10
	count := 10
	for i := 0; i < buckets; i++ {
		var hashes [][sha256.Size]byte
		for j := 0; j < count; j++ {
			hash := [sha256.Size]byte{}
			hash[0] = byte(j + i*10)
			hashes = append(hashes, hash)
		}

		// Push hashes to database.
		_, _, err = fs.Put(hashes)
		if err != nil {
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
		for j := 0; j < count; j++ {
			hash := [sha256.Size]byte{}
			hash[0] = byte(j + i*10)
			hashes = append(hashes, hash)
		}
	}

	grs, err := fs.Get(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(grs) != buckets*count {
		t.Fatalf("expected %v GetResult got %v", count, len(grs))
	}

	for i, gr := range grs {
		if !bytes.Equal(gr.Digest[:], hashes[i][:]) {
			t.Fatalf("invalid digest got %x want %x",
				gr.Digest[:], hashes[i][:])
		}
	}
}

func TestFlusherSkipNow(t *testing.T) {
	dir, err := ioutil.TempDir("", "dcrtimed.test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	fs, err := internalNew(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Set testing flag.
	fs.testing = true

	// Put batch success in current time
	var hashes [][sha256.Size]byte
	count := 10
	for i := 0; i < count; i++ {
		hash := [sha256.Size]byte{}
		hash[0] = byte(i)
		hashes = append(hashes, hash)
	}

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
