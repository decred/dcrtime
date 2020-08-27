// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/decred/dcrtime/dcrtimed/backend"
)

func NewDump(host, net, rootCert, cert, key string) (*Postgres, error) {
	// Connect to database
	dbName := net + "_dcrtime"
	h := "postgresql://" + dbUser + "@" + host + "/" + dbName
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("parse url '%v': %v", h, err)
	}

	qs := buildQueryString(rootCert, cert, key)
	addr := u.String() + "?" + qs

	db, err := sql.Open("postgres", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to database '%v': %v", addr, err)
	}

	pg := &Postgres{
		db: db,
	}

	return pg, nil
}

// Dump dumps database to the provided file descriptor. If the
// human flag is set to true it pretty prints the database content
// otherwise it dumps a JSON stream.
func (pg *Postgres) Dump(f *os.File, verbose bool) error {
	err := pg.dumpTimestamps(f, verbose)
	if err != nil {
		return err
	}
	return nil
}

func (pg *Postgres) dumpTimestamps(f *os.File, verbose bool) error {
	tss, err := pg.getAllRecordsTimestamps()
	if err != nil {
		return err
	}

	for _, ts := range *tss {
		if verbose {
			fmt.Fprintf(f, "--- Timestamp: %v\n", ts)
		}
		err = pg.dumpTimestamp(f, verbose, ts)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pg *Postgres) dumpTimestamp(f *os.File, verbose bool, ts int64) error {
	exists, records, flushTs, err := pg.getRecordsByServerTs(ts)
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
		digests  = make([]backend.DigestReceived, 0, 10000)
	)
	for _, r := range records {
		if r.MerkleRoot != [sha256.Size]byte{} && !anchored {
			anchored = true
			fr.Root = r.MerkleRoot
			fr.Tx = r.Tx
			fr.ChainTimestamp = r.AnchoredTimestamp
			fr.FlushTimestamp = flushTs
		}
		fr.Hashes = append(fr.Hashes, &r.Digest)
		digests = append(digests, backend.DigestReceived{
			Digest:    hex.EncodeToString(r.Digest[:]),
			Timestamp: r.Timestamp,
		})
	}

	if anchored {
		if verbose {
			dumpFlushRecord(f, &fr)
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
			frj := backend.FlushRecordJSON{
				Root:           fr.Root,
				Hashes:         fr.Hashes,
				Tx:             fr.Tx,
				ChainTimestamp: fr.ChainTimestamp,
				FlushTimestamp: fr.FlushTimestamp,
				Timestamp:      ts,
			}
			err = e.Encode(frj)
			if err != nil {
				return err
			}
		}
	}

	for _, v := range digests {
		err := dumpDigestTimestamp(f, verbose,
			backend.RecordTypeDigestReceived, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func dumpDigestTimestamp(f *os.File, verbose bool, recordType string, dr backend.DigestReceived) error {
	if verbose {
		fmt.Fprintf(f, "Digest     : %v\n", dr.Digest)
		fmt.Fprintf(f, "Timestamp  : %v\n", dr.Timestamp)
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

func dumpFlushRecord(f *os.File, flushRecord *backend.FlushRecord) {
	fmt.Fprintf(f, "Merkle root    : %x\n",
		flushRecord.Root)
	fmt.Fprintf(f, "Tx             : %v\n", flushRecord.Tx)
	fmt.Fprintf(f, "Chain timestamp: %v\n",
		flushRecord.ChainTimestamp)
	fmt.Fprintf(f, "Flush timestamp: %v\n",
		flushRecord.FlushTimestamp)
	for _, v := range flushRecord.Hashes {
		fmt.Fprintf(f, "  Flushed      : %x\n", *v)
	}
}
