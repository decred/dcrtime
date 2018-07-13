// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func NewDump(root string) (*FileSystem, error) {
	// Stat path first so that we don't create a database for a non
	// existing timestamp.  Leveldb WILL create a directory even if
	// ErrorIfMissing = true.
	path := filepath.Join(root, globalDBDir)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	if !fi.Mode().IsDir() {
		return nil, errInvalidDB
	}
	db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfMissing: true})
	if err != nil {
		return nil, err
	}
	return &FileSystem{root: root, db: db}, nil
}

func NewRestore(root string) (*FileSystem, error) {
	path := filepath.Join(root, globalDBDir)
	_, err := os.Stat(path)
	if err == nil {
		return nil, os.ErrExist
	}
	// Always create container.
	err = os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	// Open/create global database
	db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: true})
	if err != nil {
		return nil, err
	}
	return &FileSystem{root: root, db: db}, nil
}

func dumpDigestTimestamp(f *os.File, human bool, recordType string, dr backend.DigestReceived) error {
	if human {
		ts := ts2dirname(dr.Timestamp)
		fmt.Fprintf(f, "Digest     : %v\n", dr.Digest)
		fmt.Fprintf(f, "Timestamp  : %v -> %v\n", dr.Timestamp, ts)
	} else {
		e := json.NewEncoder(f)
		rt := backend.RecordType{
			Version: backend.RecordTypeVersion,
			Type:    recordType,
		}
		err := e.Encode(rt)
		if err != nil {
			return err
		}
		r := backend.DigestReceived{
			Digest:    dr.Digest,
			Timestamp: dr.Timestamp,
		}
		err = e.Encode(r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (fs *FileSystem) dumpGlobal(f *os.File, human bool) error {

	i := fs.db.NewIterator(nil, nil)
	defer i.Release()
	for i.Next() {
		key := hex.EncodeToString(i.Key())
		value := int64(binary.LittleEndian.Uint64(i.Value()))
		err := dumpDigestTimestamp(f, human,
			backend.RecordTypeDigestReceivedGlobal,
			backend.DigestReceived{
				Digest:    key,
				Timestamp: value,
			})
		if err != nil {
			return err
		}
	}
	return i.Error()
}

func (fs *FileSystem) dumpTimestamp(f *os.File, human bool, ts int64) error {
	db, err := fs.openRead(ts)
	if err != nil {
		return err
	}
	defer db.Close()

	digests := make([]backend.DigestReceived, 0, 10000)
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
		value := int64(binary.LittleEndian.Uint64(i.Value()))
		digests = append(digests, backend.DigestReceived{
			Digest:    hex.EncodeToString(key),
			Timestamp: value,
		})
	}

	if flushRecord != nil {
		if human {
			fmt.Fprintf(f, "Merkle root    : %x\n",
				flushRecord.Root)
			fmt.Fprintf(f, "Tx             : %v\n", flushRecord.Tx)
			fmt.Fprintf(f, "Chain timestamp: %v\n",
				flushRecord.ChainTimestamp)
			fmt.Fprintf(f, "Flush timestamp: %v\n",
				flushRecord.FlushTimestamp)
			for _, v := range flushRecord.Hashes {
				fmt.Fprintf(f, "  Hashes       : %x\n", *v)
			}
		} else {
			e := json.NewEncoder(f)
			rt := backend.RecordType{
				Version: backend.RecordTypeVersion,
				Type:    backend.RecordTypeFlushRecord,
			}
			err := e.Encode(rt)
			if err != nil {
				return err
			}
			fr := backend.FlushRecordJSON{
				Root:           flushRecord.Root,
				Hashes:         flushRecord.Hashes,
				Tx:             flushRecord.Tx,
				ChainTimestamp: flushRecord.ChainTimestamp,
				FlushTimestamp: flushRecord.FlushTimestamp,
				Timestamp:      ts,
			}
			err = e.Encode(fr)
			if err != nil {
				return err
			}
		}
	}

	for _, v := range digests {
		err := dumpDigestTimestamp(f, human,
			backend.RecordTypeDigestReceived, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fs *FileSystem) dumpTimestamps(f *os.File, human bool) error {
	files, err := ioutil.ReadDir(fs.root)
	if err != nil {
		return err
	}

	for _, fi := range files {
		if !fi.IsDir() {
			continue
		}
		if fi.Name() == globalDBDir {
			continue
		}

		// Ensure it is a valid timestamp
		t, err := time.Parse(fStr, fi.Name())
		if err != nil {
			return fmt.Errorf("invalid timestamp: %v", fi.Name())
		}

		if human {
			fmt.Fprintf(f, "--- Timestamp: %v %v\n", fi.Name(),
				t.Unix())
		}
		err = fs.dumpTimestamp(f, human, t.Unix())
		if err != nil {
			return err
		}
	}

	return nil
}

// Dump walks all directories and dumps the content to either human
// readable or JSON format.
func (fs *FileSystem) Dump(f *os.File, human bool) error {
	err := fs.dumpTimestamps(f, human)
	if err != nil {
		return err
	}
	// Dump global
	return fs.dumpGlobal(f, human)
}

// restoreOpen opens/creates a leveldb based on the timestamp that is passed
// in.
func (fs *FileSystem) restoreOpen(verbose bool, ts int64) (*leveldb.DB, error) {
	if ts <= 0 {
		return nil, fmt.Errorf("invalid timestamp: %v", ts)
	}
	path := filepath.Join(fs.root, ts2dirname(ts))
	if verbose {
		fmt.Printf("%v\n", path)
	}

	return leveldb.OpenFile(path, nil)
}

// restoreFlushRecord restores the passed flush record. It evaluates the
// timestamp it needs to be created in.
func (fs *FileSystem) restoreFlushRecord(verbose bool, fr backend.FlushRecordJSON) error {
	// Despite being expensive and slow we open and close the db in order
	// to keep the code simple and not deal with open files later.
	db, err := fs.restoreOpen(verbose, fr.Timestamp)
	if err != nil {
		return err
	}
	defer db.Close()

	frOld := backend.FlushRecord{
		Root:           fr.Root,
		Hashes:         fr.Hashes,
		Tx:             fr.Tx,
		ChainTimestamp: fr.ChainTimestamp,
		FlushTimestamp: fr.FlushTimestamp,
	}
	payload, err := EncodeFlushRecord(frOld)
	if err != nil {
		return err
	}

	return db.Put([]byte(flushedKey), payload, nil)
}

func (fs *FileSystem) restoreDigestReceived(verbose bool, dr backend.DigestReceived) error {
	// Despite being expensive and slow we open and close the db in order
	// to keep the code simple and not deal with open files later.
	db, err := fs.restoreOpen(false, dr.Timestamp)
	if err != nil {
		return err
	}
	defer db.Close()

	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(dr.Timestamp))
	hash, err := hex.DecodeString(dr.Digest)
	if err != nil {
		return err
	}

	return db.Put(hash, timestamp, nil)
}

func (fs *FileSystem) restoreDigestReceivedGlobal(verbose bool, dr backend.DigestReceived) error {
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(dr.Timestamp))
	hash, err := hex.DecodeString(dr.Digest)
	if err != nil {
		return err
	}

	return fs.db.Put(hash, timestamp, nil)
}

// Restore reads JSON encoded database contents and recreates the leveldb
// backend.
func (fs *FileSystem) Restore(f *os.File, verbose bool, location string) error {
	d := json.NewDecoder(f)
	state := 0
	for {
		switch state {
		case 0:
			// Type
			var t backend.RecordType
			err := d.Decode(&t)
			if err != nil {
				return err
			}

			// Check version we understand
			if t.Version != backend.RecordTypeVersion {
				return fmt.Errorf("unknown version %v",
					t.Version)
			}

			// Determine record type
			switch t.Type {
			case backend.RecordTypeDigestReceived:
				state = 1
			case backend.RecordTypeFlushRecord:
				state = 2
			case backend.RecordTypeDigestReceivedGlobal:
				state = 3
			default:
				return fmt.Errorf("invalid record type: %v",
					t.Type)
			}
		case 1:
			// DigestReceived
			var dr backend.DigestReceived
			err := d.Decode(&dr)
			if err != nil {
				return err
			}
			err = fs.restoreDigestReceived(verbose, dr)
			if err != nil {
				return err
			}
			state = 0
		case 2:
			// Flushrecord
			var fr backend.FlushRecordJSON
			err := d.Decode(&fr)
			if err != nil {
				return err
			}
			err = fs.restoreFlushRecord(verbose, fr)
			if err != nil {
				return err
			}
			state = 0
		case 3:
			// Global timestamp
			var dr backend.DigestReceived
			err := d.Decode(&dr)
			if err != nil {
				return err
			}
			err = fs.restoreDigestReceivedGlobal(verbose, dr)
			if err != nil {
				return err
			}
			state = 0
		default:
			// Illegal
			return fmt.Errorf("invalid state %v", state)
		}
	}
}
