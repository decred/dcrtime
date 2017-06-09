// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// This is a test utility.  DO NOT USE!

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	flushedKey = "flushed"
)

// isFlushed returns true if the provided db has been flushed.
func isFlushed(db *leveldb.DB) bool {
	found, _ := db.Has([]byte(flushedKey), nil)
	return found
}

func _main() error {
	reset := flag.Bool("reset", false, "Only reset ChainTimestamp")

	flag.Parse()

	for _, a := range flag.Args() {
		// We do all this stuff because leveldb always creates a
		// directory and populates it with LOG and LOCK.
		fi, err := os.Stat(a)
		if err != nil {
			fmt.Printf("%v: %v\n", a, err)
			continue
		}
		if !fi.Mode().IsDir() {
			fmt.Printf("%v: not a directory\n", a)
			continue
		}
		_, err = os.Stat(filepath.Join(a, "LOCK"))
		if err != nil {
			fmt.Printf("%v: no LOCK\n", a)
			continue
		}
		_, err = os.Stat(filepath.Join(a, "LOG"))
		if err != nil {
			fmt.Printf("%v: no LOG\n", a)
			continue
		}

		// Assume we have a leveldb directory at this point.
		db, err := leveldb.OpenFile(a, &opt.Options{
			ErrorIfMissing: true,
		})
		if err != nil {
			fmt.Printf("%v: leveldb.OpenFile %v\n", a, err)
			continue
		}
		var action string
		if *reset {
			// Rewrite flush record.
			var fr *backend.FlushRecord
			payload, err := db.Get([]byte(flushedKey), nil)
			if err != nil {
				db.Close()
				fmt.Printf("%v: Get %v\n", a, err)
				continue
			}
			fr, err = filesystem.DecodeFlushRecord(payload)
			if err != nil {
				db.Close()
				fmt.Printf("%v: decode %v\n", a, err)
				continue
			}
			fr.ChainTimestamp = 0
			payload, err = filesystem.EncodeFlushRecord(*fr)
			if err != nil {
				db.Close()
				fmt.Printf("%v: encode %v\n", a, err)
				continue
			}
			err = db.Put([]byte(flushedKey), payload, nil)
			if err != nil {
				db.Close()
				fmt.Printf("%v: Put %v\n", a, err)
				continue
			}
			action = "reset"
		} else {
			// Delete record.
			err = db.Delete([]byte(flushedKey), nil)
			if err != nil {
				db.Close()
				fmt.Printf("%v: leveldb.Delete %v\n", a, err)
				continue
			}
			action = "unflushed"
		}
		db.Close()

		fmt.Printf("%v: %v\n", action, a)
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
