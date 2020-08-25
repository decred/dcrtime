// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/decred/dcrd/txscript/v2"
	"github.com/decred/dcrdata/api/types/v4"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/merkle"
)

const (
	PostgresActionVersion = 1 // All structure versions

	PostgresActionHeader          = "header"
	PostgresActionDeleteTimestamp = "deletetimestamp"
	PostgresActionDeleteDigest    = "deletedigest"
	PostgresActionDeleteDuplicate = "deleteduplicate"
)

type PostgresAction struct {
	Version   uint64 `json:"version"`   // Version of structure
	Timestamp int64  `json:"timestamp"` // Timestamp of action
	Action    string `json:"action"`    // Following JSON command
}

type PostgresHeader struct {
	Version uint64 `json:"version"` // Version of structure
	Start   int64  `json:"start"`   // Start of fsck
	DryRun  bool   `json:"dryrun"`  // Dry run
}

type PostgresDeleteTimestamp struct {
	Version   uint64 `json:"version"`   // Version of structure
	Timestamp int64  `json:"timestamp"` // Timestamp
	Directory string `json:"directory"` // Directory name of Timestamp
}

type PostgresDeleteDigest struct {
	Version         uint64 `json:"version"`         // Version of structure
	Timestamp       int64  `json:"timestamp"`       // Timestamp of digest
	GlobalTimestamp int64  `json:"globaltimestamp"` // Global timestamp of digest
	Digest          string `json:"digest"`          // Digest that was deleted
}

type PostgresDeleteDuplicate struct {
	Version            uint64 `json:"version"`            // Version of structure
	Digest             string `json:"digest"`             // Duplicate digest
	Found              int64  `json:"found"`              // Original timestamp
	FoundDirectory     string `json:"founddirectory"`     // Original directory
	Duplicate          int64  `json:"duplicate"`          // Duplicate timestamp
	DuplicateDirectory string `json:"duplicatedirectory"` // Duplicate directory
}

// validJournalAction returns true if the action is a valid PostgresAction.
func validJournalAction(action string) bool {
	switch action {
	case PostgresActionHeader:
	case PostgresActionDeleteTimestamp:
	case PostgresActionDeleteDigest:
	case PostgresActionDeleteDuplicate:
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

	// Write PostgresAction
	e := json.NewEncoder(f)
	rt := PostgresAction{
		Version:   PostgresActionVersion,
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
// 1.  Find timestamp' digests in records table & anchor db info if anchored
// 2.  Ensure no duplicates in timestamp's digets
// 3.  If timestamp was anchored:
// 3.1 Generate merkle root using records table digests and verify against
//     anchor's merkle root from db
// 3.2 Verify that the anchor merkle root on db exists on the blockchain.
func (pg *Postgres) fsckTimestamp(options *backend.FsckOptions, ts int64) error {
	exists, records, err := pg.getRecordsByServerTs(ts)
	if err != nil {
		return err
	}
	// Non fatal error if there is nothing to do
	if !exists {
		return nil
	}

	var (
		anchored bool
		fr       backend.FlushRecord
	)
	digests := make(map[string]int64)
	for _, r := range records {
		k := hex.EncodeToString(r.Digest[:])
		if _, ok := digests[k]; ok {
			// This really can't happen but we check it so that we
			// can equate lengths later to determine if the map and
			// array are the same.
			return fmt.Errorf("    *** ERROR duplicate key: %v", k)
		}
		digests[k] = ts
		if r.MerkleRoot != [sha256.Size]byte{} {
			anchored = true
			fr.Root = r.MerkleRoot
			fr.Tx = r.Tx
		}
		fr.Hashes = append(fr.Hashes, &r.Digest)
	}

	// If anchored generate merkle and compare against merkle in anchors
	// table
	if anchored {
		// Generate merkle
		mt := merkle.Tree(fr.Hashes)
		// Last element is root
		root := *mt[len(mt)-1]
		if !bytes.Equal(root[:], fr.Root[:]) {
			return fmt.Errorf("   *** ERROR mismatched merkle "+
				"root: %x %x", root, fr.Root)
		}
	}

	// 3.3 Verify merkle root in tx
	u := options.URL + fr.Tx.String() + "/out"
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
			return fmt.Errorf("   *** ERROR invalid "+
				"dcrdata script: %v", err)
		}
		data, err := txscript.PushedData(script)
		if err != nil {
			return fmt.Errorf("   *** ERROR invalid "+
				"script: %v", err)
		}
		if !bytes.Equal(data[0], fr.Root[:]) {
			continue
		}

		// Everything is cool so mark it and break out
		done = true
		break
	}

	if !done {
		return fmt.Errorf("   *** ERROR merkle root not "+
			"found: tx %v merkle %x", fr.Tx, fr.Root)
	}

	return nil
}

func (pg *Postgres) fsckTimestamps(options *backend.FsckOptions) error {
	tss, err := pg.getAllRecordsTimestamps()
	if err != nil {
		return err
	}

	for _, ts := range *tss {
		if options.Verbose || options.PrintHashes {
			fmt.Printf("--- Checking: %v \n", ts)
		}
		err = pg.fsckTimestamp(options, ts)
		if err != nil {
			return err
		}
		if options.Verbose || options.PrintHashes {
			fmt.Printf("=== Verified: %v \n",
				ts)
		}
	}
	return nil
}

// Fsck walks all db records and verifies all that there is no apparent data
// corruption and that the anchors indeed exist on the blockchain.
func (pg *Postgres) Fsck(options *backend.FsckOptions) error {
	ts := time.Now().Unix()
	fmt.Printf("=== FSCK started %v\n", ts)
	fmt.Printf("--- Phase 1: checking records table\n")

	if options.File != "" {
		// Create journal file
		f, err := os.OpenFile(options.File, os.O_RDWR|os.O_CREATE, 0640)
		if err != nil {
			return err
		}
		f.Close()
	}

	err := journal(options.File, PostgresActionHeader,
		PostgresHeader{
			Version: PostgresActionVersion,
			Start:   ts,
			DryRun:  !options.Fix,
		})
	if err != nil {
		return fmt.Errorf("   *** ERROR journal: %v",
			err)
	}

	if options == nil {
		options = &backend.FsckOptions{}
	}

	err = pg.fsckTimestamps(options)
	if err != nil {
		return err
	}
	return nil
}
