// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"crypto/sha256"
	"os"
	"sync"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/dcrtimewallet"
	"github.com/robfig/cron"
)

var (
	_ backend.Backend = (*Postgres)(nil)

	// duration and flushSchedule must match or bad things will happen. By
	// matching we mean both are hourly or every so many minutes.
	//
	// Seconds Minutes Hours Days Months DayOfWeek
	flushSchedule = "10 0 * * * *" // On the hour + 10 seconds
	duration      = time.Hour      // Default how often we combine digests
)

// Postgres is a postgreSQL implementation of a backend, it stores all uploaded
// digests in records table, on flush it stores all anchor info as well and
// link all anchored records with the corresponding anchor.
type Postgres struct {
	sync.RWMutex

	cron *cron.Cron // Scheduler for periodic tasks
	// db       *leveldb.DB   // Global database [hash]timestamp
	duration time.Duration // How often we combine digests
	commit   uint          // Current version, incremented during flush

	wallet *dcrtimewallet.DcrtimeWallet // Wallet context.
}

// Return timestamp information for given digests.
func (pg *Postgres) Get([][sha256.Size]byte) ([]backend.GetResult, error) {
	return nil, nil
}

// Return all hashes for given timestamps.
func (pg *Postgres) GetTimestamps([]int64) ([]backend.TimestampResult, error) {
	return nil, nil
}

// Store hashes and return timestamp and associated errors.  Put is
// allowed to return transient errors.
func (pg *Postgres) Put([][sha256.Size]byte) (int64, []backend.PutResult, error) {
	return 0, nil, nil
}

// Close performs cleanup of the backend.
func (pg *Postgres) Close() {
}

// Dump dumps database to the provided file descriptor. If the
// human flag is set to true it pretty prints the database content
// otherwise it dumps a JSON stream.
func (pg *Postgres) Dump(*os.File, bool) error {
	return nil
}

// Restore recreates the the database from the provided file
// descriptor. The verbose flag is set to true to indicate that this
// call may parint to stdout. The provided string describes the target
// location and is implementation specific.
func (pg *Postgres) Restore(*os.File, bool, string) error {
	return nil
}

// Fsck walks all data and verifies its integrity. In addition it
// verifies anchored timestamps' existence on the blockchain.
func (pg *Postgres) Fsck(*backend.FsckOptions) error {
	return nil
}

// GetBalance retrieves balance information for the wallet
// backing this instance
func (pg *Postgres) GetBalance() (*backend.GetBalanceResult, error) {
	return nil, nil
}

// LastAnchor retrieves last successful anchor details
func (pg *Postgres) LastAnchor() (*backend.LastAnchorResult, error) {
	return nil, nil
}
