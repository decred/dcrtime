// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

// dumpGlobal dumps the global dir and creates a timestamp and digest lookup
// map.  The map is [timestamp directory] digest.
func dumpGlobal(directory string) (map[string][][]byte, map[string]int64, error) {
	db, err := leveldb.OpenFile(directory, nil)
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	i := db.NewIterator(nil, nil)
	rl := make(map[string][][]byte)
	lookup := make(map[string]int64)
	for i.Next() {
		fmt.Printf("%v\n", strings.Repeat("=", 80))
		key := i.Key()
		value := int64(binary.LittleEndian.Uint64(i.Value()))
		ts := ts2dirname(value)
		fmt.Printf("key     : %x\n", key)
		fmt.Printf("Record  : %v -> %v\n", value, ts)

		// Store timestamp to check later
		digests := rl[ts]
		rl[ts] = append(digests, key)

		lookup[hex.EncodeToString(key)] = value
	}
	i.Release()
	return rl, lookup, i.Error()
}

// DumpAll dumps all databases to stdout.  Must be called with dcrtimed not
// running.  It may fail opening databases otherwise.
func DumpAll(fsRoot string) error {
	// Read dir and find all databases
	files, err := ioutil.ReadDir(fsRoot)
	if err != nil {
		return err
	}

	fmt.Printf("Database: %v\n", fsRoot)

	// Only look at valid timestamps and global, if we find anything that
	// isn't that we bomb because the user picked the wrong dir.
	type TimestampTuple struct {
		timestamp int64
		directory string
	}
	var (
		rl   map[string][][]byte
		l    map[string]int64
		work []TimestampTuple
	)
	for _, fi := range files {
		if !fi.IsDir() {
			return fmt.Errorf("not a dir: %v", fi.Name())
		}
		if fi.Name() == globalDBDir {
			rl, l, err = dumpGlobal(filepath.Join(fsRoot, fi.Name()))
			if err != nil {
				return err
			}
			continue
		}
		t, err := time.Parse(fStr, fi.Name())
		if err != nil {
			return fmt.Errorf("invalid timestamp: %v", fi.Name())
		}

		work = append(work, TimestampTuple{
			timestamp: t.Unix(),
			directory: fi.Name(),
		})
	}

	// Walk work and compare to global
	for _, timestamp := range work {
		fmt.Printf("%v\n", strings.Repeat("-", 80))
		fmt.Printf("Timestamp directory: %v\n", timestamp.directory)
		fmt.Printf("Timestamp          : %v\n", timestamp.timestamp)
		_, found := rl[timestamp.directory]
		if !found {
			fmt.Printf("%v: does not exist in global db\n",
				timestamp.directory)
		}

		// Dump record
		db, err := leveldb.OpenFile(filepath.Join(fsRoot,
			timestamp.directory), nil)
		if err != nil {
			// Just abort, this should work since it is vetted
			return err
		}
		// Iterate to make sure there is only one record
		var (
			fr *backend.FlushRecord
		)
		iter := db.NewIterator(nil, nil)
		count := 0
		unflushedCount := 0
		for iter.Next() {
			key := iter.Key()
			if string(key) == flushedKey {
				if fr != nil {
					return fmt.Errorf("multi flushed records")
				}
				fr, err = DecodeFlushRecord(iter.Value())
				if err != nil {
					return err
				}
				continue
			}

			// Dump key (digest) and value (timestamp)
			var value int64
			fmt.Printf("  Key      : %x\n", key)
			if len(iter.Value()) == 0 {
				fmt.Printf("  Timestamp: not flushed\n")
				unflushedCount++
			} else {
				count++
				value = int64(binary.LittleEndian.Uint64(iter.Value()))
				ts := ts2dirname(value)
				fmt.Printf("  Timestamp: %v -> %v\n", value, ts)
			}

			// See if we exist in global db
			if foundTs, ok := l[hex.EncodeToString(key)]; ok {
				fmt.Printf("    Found: key %x timestamp %v\n",
					key, foundTs)
				if foundTs != value {
					fmt.Printf("    Found timestamp INVALID: %v %v %v %x\n",
						timestamp, foundTs, value, key)
				}
				continue
			}
			fmt.Printf("    Not found timestamp: %v %xn",
				timestamp, key)
		}
		iter.Release()
		err = iter.Error()
		if err != nil {
			db.Close()
			return err
		}
		db.Close()

		fmt.Printf("Flush record: %v", spew.Sdump(fr))
		fmt.Printf("Flushed  : %v\n", count)
		fmt.Printf("Unflushed: %v\n", unflushedCount)
	}

	return nil
}
