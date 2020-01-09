// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/txscript/v2"
	"github.com/decred/dcrdata/api/types/v4"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/merkle"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	FilesystemActionVersion = 1 // All structure versions

	FilesystemActionHeader          = "header"
	FilesystemActionDeleteTimestamp = "deletetimestamp"
	FilesystemActionDeleteDigest    = "deletedigest"
	FilesystemActionDeleteDuplicate = "deleteduplicate"
)

type FilesystemAction struct {
	Version   uint64 `json:"version"`   // Version of structure
	Timestamp int64  `json:"timestamp"` // Timestamp of action
	Action    string `json:"action"`    // Following JSON command
}

type FilesystemHeader struct {
	Version uint64 `json:"version"` // Version of structure
	Start   int64  `json:"start"`   // Start of fsck
	DryRun  bool   `json:"dryrun"`  // Dry run
}

type FilesystemDeleteTimestamp struct {
	Version   uint64 `json:"version"`   // Version of structure
	Timestamp int64  `json:"timestamp"` // Timestamp
	Directory string `json:"directory"` // Directory name of Timestamp
}

type FilesystemDeleteDigest struct {
	Version         uint64 `json:"version"`         // Version of structure
	Timestamp       int64  `json:"timestamp"`       // Timestamp of digest
	GlobalTimestamp int64  `json:"globaltimestamp"` // Global timestamp of digest
	Digest          string `json:"digest"`          // Digest that was deleted
}

type FilesystemDeleteDuplicate struct {
	Version            uint64 `json:"version"`            // Version of structure
	Digest             string `json:"digest"`             // Duplicate digest
	Found              int64  `json:"found"`              // Original timestamp
	FoundDirectory     string `json:"founddirectory"`     // Original directory
	Duplicate          int64  `json:"duplicate"`          // Duplicate timestamp
	DuplicateDirectory string `json:"duplicatedirectory"` // Duplicate directory
}

// validJournalAction returns true if the action is a valid FilesystemAction.
func validJournalAction(action string) bool {
	switch action {
	case FilesystemActionHeader:
	case FilesystemActionDeleteTimestamp:
	case FilesystemActionDeleteDigest:
	case FilesystemActionDeleteDuplicate:
	default:
		return false
	}
	return true
}

// journal records what fix occurred at what time if filename != "".
func journal(filename, action string, payload interface{}) error {
	// See if we are journaling
	if filename == "" {
		return nil
	}

	// Sanity
	if !validJournalAction(action) {
		return fmt.Errorf("invalid journal action: %v", action)
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write FilesystemAction
	e := json.NewEncoder(f)
	rt := FilesystemAction{
		Version:   FilesystemActionVersion,
		Timestamp: time.Now().Unix(),
		Action:    action,
	}
	err = e.Encode(rt)
	if err != nil {
		return err
	}

	// Write payload
	err = e.Encode(payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "\n")

	return err
}

// fsckTimestamp verifies that a timestamp is coherent by doing the following:
// 1.  Find flushRecord
// 2.  If flushRecord doesn't exist ensure that the digests do not exist in the
//     global database.
// 3.  If flushRecord does exist ensure that all digests in the database are
//     represented inside the flushRecord.
// 3.1 Verify merkle against flushRecord merkle
// 3.2 Ensure that all digests in the database exist in the global database and
//     the timestamps matches the global timestamp directory.
// 3.3 Verify that the flushRecord timestamp exists on the blockchain.
func (fs *FileSystem) fsckTimestamp(options *backend.FsckOptions, ts int64, empties map[int64]struct{}) error {
	db, err := fs.openRead(ts)
	if err != nil {
		return err
	}
	defer db.Close()

	digests := make(map[string]int64)
	var flushRecord *backend.FlushRecord

	i := db.NewIterator(nil, nil)
	defer i.Release()
	for i.Next() {
		key := i.Key()
		if string(key) == flushedKey {
			flushRecord, err = DecodeFlushRecord(i.Value())
			if err != nil {
				return err
			}
			continue
		}
		k := hex.EncodeToString(key)
		if _, ok := digests[k]; ok {
			// This really can't happen but we check it so that we
			// can equate lengths later to determine if the map and
			// array are the same.
			return fmt.Errorf("    *** ERROR duplicate key: %v", k)
		}
		digests[k] = int64(binary.LittleEndian.Uint64(i.Value()))
	}

	// Non fatal error if there is nothing to do
	if len(digests) == 0 && flushRecord == nil {
		// We store the timestamp so that we can cross check with
		// global database later. If there is no pointer back to this
		// timestamp we can safely delete it.
		if _, ok := empties[ts]; ok {
			// This should not happen
			return fmt.Errorf("   *** ERROR duplicate timestamp "+
				"in empties: %v", ts)
		}
		empties[ts] = struct{}{}
		fmt.Printf("   *** ERROR empty timestamp: %v (%v)\n",
			ts2dirname(ts), ts)
		return nil
	}

	if flushRecord != nil {
		if options.Verbose {
			dumpFlushRecord(os.Stdout, flushRecord)
		}

		// 3. Make sure all digests exist in flush record
		if len(digests) != len(flushRecord.Hashes) {
			// XX Dump hashes
			return fmt.Errorf("   *** ERROR mismatched len: %v %v",
				len(digests), len(flushRecord.Hashes))
		}
		for _, v := range flushRecord.Hashes {
			hash := hex.EncodeToString(v[:])
			if _, ok := digests[hash]; !ok {
				return fmt.Errorf("   *** ERROR unknown hash: %v",
					hash)
			}

			// Since we check for length and use a map we know
			// there are no dups so hijack this for PrintHashes.
			if options.PrintHashes {
				fmt.Printf("Hash           : %v\n", hash)
			}
		}

		// 3.1 Recreate merkle and verify it
		root := merkle.Root(flushRecord.Hashes)
		if !bytes.Equal(root[:], flushRecord.Root[:]) {
			return fmt.Errorf("   *** ERROR mismatched merkle "+
				"root: %x %x", *root, flushRecord.Root)
		}

		// 3.2 verify that all digests exist in global db and verify
		// timestamp points to the correct container.
		for _, v := range flushRecord.Hashes {
			gdbts, err := fs.db.Get(v[:], nil)
			if err != nil {
				return fmt.Errorf("   *** ERROR not found in "+
					"db: %x", v)
			}
			dbts := int64(binary.LittleEndian.Uint64(gdbts))
			if dbts != ts {
				return fmt.Errorf("   *** ERROR timestamp "+
					"mismatch: %v %v", dbts, ts)
			}
		}

		// 3.3 Verify merkle root in tx
		u := options.URL + flushRecord.Tx.String() + "/out"
		r, err := http.Get(u)
		if err != nil {
			return fmt.Errorf("   *** ERROR HTTP Get: %v", err)
		}
		defer r.Body.Close()

		if r.StatusCode != http.StatusOK {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return fmt.Errorf("   *** ERROR invalid "+
					"body: %v %v", r.StatusCode, body)
			}
			return fmt.Errorf("   *** ERROR invalid dcrdata "+
				"answer: %v %s", r.StatusCode, body)
		}

		var txOuts []types.TxOut
		d := json.NewDecoder(r.Body)
		if err := d.Decode(&txOuts); err != nil {
			return err
		}

		var done bool
		for _, v := range txOuts {
			if !types.IsNullDataScript(v.ScriptPubKeyDecoded.Type) {
				continue
			}
			script, err := hex.DecodeString(v.ScriptPubKeyDecoded.Hex)
			if err != nil {
				// XXX bad error, fix
				return fmt.Errorf("   *** ERROR invalid "+
					"dcrdata script: %v", err)
			}
			data, err := txscript.PushedData(script)
			if err != nil {
				// XXX bad error, fix
				return fmt.Errorf("   *** ERROR invalid "+
					"script: %v", err)
			}
			if !bytes.Equal(data[0], flushRecord.Root[:]) {
				continue
			}

			// Everything is cool so mark it and break out
			done = true
			break
		}
		if !done {
			return fmt.Errorf("   *** ERROR merkle root not "+
				"found: tx %v merkle %x", flushRecord.Tx,
				flushRecord.Root)
		}

		// We are done
		return nil
	}

	// 2. Make sure timestamps do not exist in the global database
	for k := range digests {
		key, err := hex.DecodeString(k)
		if err != nil {
			return fmt.Errorf("   *** ERROR internal error on "+
				"key: %v", k)
		}

		if options.PrintHashes {
			fmt.Printf("     Unflushed    : %v\n", k)
		}

		gdbts, err := fs.db.Get(key, nil)
		if err != nil {
			if err == leveldb.ErrNotFound {
				continue
			}
			return fmt.Errorf("   *** ERROR found in db: %v %v",
				k, err)
		}
		dbts := int64(binary.LittleEndian.Uint64(gdbts))
		if dbts != ts {
			// This is the result of a bug that was caused when the
			// server was shutdown over a flush window and the user
			// submitted the same hash again.
			// The bug that caused this has since been fixed.
			fmt.Printf("   *** ERROR timestamp mismatch: %v %v %v\n",
				k, dbts, ts)

			// Record action before verifying Fix
			err = journal(options.File, FilesystemActionDeleteDigest,
				FilesystemDeleteDigest{
					Version:         FilesystemActionVersion,
					Timestamp:       ts,
					GlobalTimestamp: dbts,
					Digest:          k,
				})
			if err != nil {
				return fmt.Errorf("   *** ERROR journal: %v",
					err)
			}

			if !options.Fix {
				continue
			}

			fmt.Printf("   *** FIXING timestamp mismatch: delete "+
				"%v %v\n", k, ts)
			err = db.Delete(key, nil)
			if err != nil {
				return fmt.Errorf("   *** ERROR timestamp " +
					"mismatch: delete")
			}
			delete(digests, k)
		}
	}

	// Check again and add to empties. We may have deleted the last record
	// while fixing timestamp mismatches.
	if len(digests) == 0 {
		empties[ts] = struct{}{}
	}

	return nil
}

func (fs *FileSystem) fsckTimestamps(options *backend.FsckOptions, empties map[int64]struct{}) error {
	files, err := ioutil.ReadDir(fs.root)
	if err != nil {
		return err
	}

	for _, fi := range files {
		if !fi.IsDir() {
			return fmt.Errorf("Unexpected file %v",
				filepath.Join(fs.root, fi.Name()))
		}
		if fi.Name() == globalDBDir {
			continue
		}

		// Ensure it is a valid timestamp
		t, err := time.Parse(fStr, fi.Name())
		if err != nil {
			return fmt.Errorf("invalid timestamp: %v", fi.Name())
		}

		if options.Verbose || options.PrintHashes {
			fmt.Printf("--- Checking: %v (%v)\n", fi.Name(),
				t.Unix())
		}
		err = fs.fsckTimestamp(options, t.Unix(), empties)
		if err != nil {
			return err
		}
		if options.Verbose || options.PrintHashes {
			fmt.Printf("=== Verified: %v (%v)\n", fi.Name(),
				t.Unix())
		}
	}

	return nil
}

func (fs *FileSystem) fsckExists(ts int64, hash []byte) (bool, error) {
	db, err := fs.openRead(ts)
	if err != nil {
		return false, err
	}
	defer db.Close()

	return db.Has(hash, nil)
}

// fsckGlobal walks the global database and verifies that the timestamps are
// indeed represented in the timestamp directory.
func (fs *FileSystem) fsckGlobal(options *backend.FsckOptions, empties map[int64]struct{}) error {
	i := fs.db.NewIterator(nil, nil)
	defer i.Release()
	for i.Next() {
		key := hex.EncodeToString(i.Key())
		value := int64(binary.LittleEndian.Uint64(i.Value()))
		if options.PrintHashes {
			fmt.Printf("Flushed        : %v\n", key)
		}
		found, err := fs.fsckExists(value, i.Key())
		if err != nil {
			return err
		}
		if !found {
			// Really no good way of dealing with this but let's
			// enumerate the scenarios.
			//
			// Only thing we can do is walking ALL timestamps
			// looking for this hash and see if there is a record
			// of it at all. If there isn't we can delete it but it
			// should have never happened.
			//
			// If it is found ONCE then the global record needs to
			// be rewritten with the correct timestamp.
			//
			// If it is found multiple times we need to look for a
			// flushRecord to see if it made it to the blockchain.
			// If it exists in multiple flushRecords it is game
			// over. Human needs to something. What something is
			// unclear and should be dealt with on a case by case
			// basis.
			//
			// At this point we treat this as fatal because there
			// is no need to write code for theoretical issues that
			// should not have happned.
			return fmt.Errorf("   *** ERROR hash not found in "+
				"timestamp : %v %v\n", filepath.Join(fs.root,
				ts2dirname(value)), key)
		}

		// Check to see if this timestamp exists in the empties map.
		// This is bad because if it is we have an empty timestamp
		// directory while the global directory thinks there should be
		// a record.
		if _, ok := empties[value]; ok {
			// There really is no good recovery from this. A
			// potential solution would be to create a record but
			// it may be inaccurate.
			//
			// At this point we treat this as fatal because there
			// is no need to write code for theoretical issues that
			// should not have happned.
			return fmt.Errorf("   *** ERROR global pointer to "+
				"empty timestamp: %v (%v)", ts2dirname(value),
				value)
		}
	}
	if i.Error() != nil {
		return i.Error()
	}

	// Range over empties and try to delete them.
	for k := range empties {
		// Record action before verifying Fix
		err := journal(options.File, FilesystemActionDeleteTimestamp,
			FilesystemDeleteTimestamp{
				Version:   FilesystemActionVersion,
				Timestamp: k,
				Directory: ts2dirname(k),
			})
		if err != nil {
			return fmt.Errorf("   *** ERROR journal: %v",
				err)
		}

		if !options.Fix {
			continue
		}

		// It is safe to delete the timestamp directory. The reason
		// these directories exist is because leveldb has a bug that it
		// always creates the container directory despite being told
		// not to. This bug was not worked around in early dcrtime
		// deployments but has since been fixed.
		fmt.Printf("   *** FIXING removing empty timestamp: %v (%v)\n",
			ts2dirname(k), k)
		path := filepath.Join(fs.root, ts2dirname(k))
		err = os.RemoveAll(path)
		if err != nil {
			return fmt.Errorf("   *** ERROR RemoveAll: %v", err)
		}
		delete(empties, k)
	}
	// Make sure we don't have any empties left over
	if len(empties) != 0 && options.Fix {
		// Shouldn't happen
		return fmt.Errorf("   *** ERROR empties not pruned: %v ",
			spew.Sdump(empties))
	}

	return nil
}

// fsckDup checks for duplicate digests in the global dups map.
func (fs *FileSystem) fsckDup(options *backend.FsckOptions, ts int64, dups map[string]int64) error {
	db, err := fs.openRead(ts)
	if err != nil {
		return err
	}
	defer db.Close()

	i := db.NewIterator(nil, nil)
	defer i.Release()
	for i.Next() {
		key := i.Key()
		if string(key) == flushedKey {
			// Skip FlushRecord
			flushRecord, err := DecodeFlushRecord(i.Value())
			if err != nil {
				return err
			}
			if options.Verbose {
				dumpFlushRecord(os.Stdout, flushRecord)
			}
			continue
		}
		k := hex.EncodeToString(key)
		if options.PrintHashes {
			fmt.Printf("Hash           : %v\n", k)
		}
		if v, ok := dups[k]; ok {
			// This is the result of a bug that was caused when the
			// server was shutdown over a flush window and the user
			// submitted the same hash again.
			// The bug that caused this has since been fixed.
			//
			// The only thing we can do is assert (which should
			// have been caught!) that there is no entry in the
			// global db and delete the duplicate entry. This is
			// safe because the caller has not caused a flush yet
			// and therefore has no record YET of which TX it lives
			// in.
			fmt.Printf("    *** ERROR duplicate key: %v %v %v\n",
				ts, v, k)

			// Record action before verifying Fix
			err := journal(options.File, FilesystemActionDeleteDuplicate,
				FilesystemDeleteDuplicate{
					Version:            FilesystemActionVersion,
					Digest:             k,
					Found:              v,
					FoundDirectory:     ts2dirname(v),
					Duplicate:          ts,
					DuplicateDirectory: ts2dirname(ts),
				})
			if err != nil {
				return fmt.Errorf("   *** ERROR journal: %v",
					err)
			}

			if !options.Fix {
				continue
			}

			// 1. Verify against global db
			ok, err := fs.db.Has(key, nil)
			if err != nil {
				return fmt.Errorf("   *** ERROR duplicate "+
					"key: has %v", err)
			}
			if ok {
				return fmt.Errorf("   *** ERROR duplicate "+
					"key: exists in global %v", k)
			}

			// 2. Delete current record
			err = db.Delete(key, nil)
			if err != nil {
				return fmt.Errorf("   *** ERROR duplicate " +
					"key: delete")
			}
			fmt.Printf("    *** FIXING duplicate key: delete "+
				"%v %v\n", ts, k)
			continue
		}
		dups[k] = int64(binary.LittleEndian.Uint64(i.Value()))
	}
	return i.Error()
}

// fsckDups checks for duplicate digests in all timestamp containers.
func (fs *FileSystem) fsckDups(options *backend.FsckOptions) error {
	files, err := ioutil.ReadDir(fs.root)
	if err != nil {
		return err
	}

	digests := make(map[string]int64)
	for _, fi := range files {
		if !fi.IsDir() {
			return fmt.Errorf("Unexpected file %v",
				filepath.Join(fs.root, fi.Name()))
		}
		if fi.Name() == globalDBDir {
			continue
		}

		// Ensure it is a valid timestamp
		t, err := time.Parse(fStr, fi.Name())
		if err != nil {
			return fmt.Errorf("invalid timestamp: %v", fi.Name())
		}

		if options.Verbose || options.PrintHashes {
			fmt.Printf("--- Checking: %v (%v)\n", fi.Name(),
				t.Unix())
		}
		err = fs.fsckDup(options, t.Unix(), digests)
		if err != nil {
			return err
		}
		if options.Verbose || options.PrintHashes {
			fmt.Printf("=== Verified: %v (%v)\n", fi.Name(),
				t.Unix())
		}
	}

	return nil
}

// Fsck walks all directories and verifies all that there is no apparent data
// corruption and that the flush records indeed exist on the blockchain.
func (fs *FileSystem) Fsck(options *backend.FsckOptions) error {
	t := time.Now()
	fmt.Printf("=== FSCK started %v\n", t.Format(time.UnixDate))
	fmt.Printf("--- Phase 1: checking timestamp directories\n")

	if options.File != "" {
		// Create journal file
		f, err := os.OpenFile(options.File, os.O_RDWR|os.O_CREATE, 0640)
		if err != nil {
			return err
		}
		f.Close()
	}

	err := journal(options.File, FilesystemActionHeader,
		FilesystemHeader{
			Version: FilesystemActionVersion,
			Start:   t.Unix(),
			DryRun:  !options.Fix,
		})
	if err != nil {
		return fmt.Errorf("   *** ERROR journal: %v",
			err)
	}

	if options == nil {
		options = &backend.FsckOptions{}
	}

	empties := make(map[int64]struct{})
	err = fs.fsckTimestamps(options, empties)
	if err != nil {
		return err
	}

	fmt.Printf("--- Phase 2: checking global timestamp database\n")
	err = fs.fsckGlobal(options, empties)
	if err != nil {
		return err
	}

	fmt.Printf("--- Phase 3: checking duplicate digests\n")
	defer func() {
		fmt.Printf("=== FSCK completed %v\n",
			time.Now().Format(time.UnixDate))
	}()

	return fs.fsckDups(options)
}
