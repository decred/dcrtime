// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/dcrtimewallet"
	"github.com/decred/dcrtime/merkle"
	"github.com/lib/pq"
	"github.com/robfig/cron"
)

const (
	tableRecords  = "records"
	tableAnchors  = "anchors"
	dbUser        = "dcrtimed"
	confirmations = 6

	// error codes that are overridden during tests only.
	// digestFound is thrown if digest was found in records table
	digestFound = 1001
)

var (
	_ backend.Backend = (*Postgres)(nil)

	// duration and flushSchedule must match or bad things will happen. By
	// matching we mean both are hourly or every so many minutes.
	//
	// Seconds Minutes Hours Days Months DayOfWeek
	flushSchedule = "10 0 * * * *" // On the hour + 10 seconds
	duration      = time.Hour      // Default how often we combine digests

	errEmptySet = errors.New("empty set")
)

// Postgres is a postgreSQL implementation of a backend, it stores all uploaded
// digests in records table, on flush it stores all anchor info as well and
// link all anchored records with the corresponding anchor.
type Postgres struct {
	sync.RWMutex

	cron     *cron.Cron    // Scheduler for periodic tasks
	db       *sql.DB       // Postgres database
	duration time.Duration // How often we combine digests
	commit   uint          // Current version, incremented during flush

	enableCollections bool // Set to true to enable collection query

	wallet *dcrtimewallet.DcrtimeWallet // Wallet context.

	// testing only entries
	myNow   func() time.Time // Override time.Now()
	testing bool             // Enabled during test
}

// now returns current time stamp rounded down to 1 hour.  All timestamps are
// UTC.
func (pg *Postgres) now() time.Time {
	return pg.truncate(pg.myNow().UTC(), pg.duration)
}

// truncate rounds time down to the provided duration.  This is split out in
// order to test.
func (pg *Postgres) truncate(t time.Time, d time.Duration) time.Time {
	return t.Truncate(d)
}

var (
	errInvalidConfirmations  = errors.New("invalid confirmations")
	errNotEnoughConfirmation = errors.New("not enough confirmations")
)

// lazyFlush takes a pointer to a flush record and updates the chain anchor
// timestamp of said record and writes it back to the database and returns
// the result of the wallet's Lookup function
//
// IMPORTANT NOTE: We *may* write to the anchors database in case of a lazy
// timestamp update to the anchor timestamo while holding the READ lock.  This
// is OK because at worst we are racing multiple atomic writes.
// This is suboptimal but beats taking a write lock for all get* calls.
func (pg *Postgres) lazyFlush(fr *backend.FlushRecord) (*dcrtimewallet.TxLookupResult, error) {
	res, err := pg.wallet.Lookup((*fr).Tx)
	if err != nil {
		return nil, err
	}

	log.Debugf("lazyFlush confirmations: %v", res.Confirmations)

	if res.Confirmations == -1 {
		return nil, errInvalidConfirmations
	} else if res.Confirmations < confirmations {
		// Return error & wallet lookup res
		// for error handling
		return res, errNotEnoughConfirmation
	}

	fr.ChainTimestamp = res.Timestamp

	// Update anchor row in database
	err = pg.updateAnchorChainTs(fr)
	if err != nil {
		return nil, err
	}

	log.Infof("Flushed anchor timestamp: %v %v", fr.Tx.String(),
		res.Timestamp)

	return res, nil
}

// Return timestamp information for given digests.
func (pg *Postgres) Get(digests [][sha256.Size]byte) ([]backend.GetResult, error) {
	gdmes := make([]backend.GetResult, 0, len(digests))

	// We need to be read locked from here on out.  Note that we are not
	// locking/releasing.  This is by design in order to let all readers
	// finish before a potential write occurs.
	pg.RLock()
	defer pg.RUnlock()

	// Iterate over digests and translate results to backend interface.
	for _, d := range digests {
		gdme := backend.GetResult{
			Digest: d,
		}
		found, err := pg.getRecordByDigest(d[:], &gdme)
		if err != nil {
			return nil, err
		}

		if !found {
			gdme.ErrorCode = backend.ErrorNotFound
		} else {
			// Override error code during testing
			if pg.testing {
				gdme.ErrorCode = digestFound
			} else if gdme.MerkleRoot != [sha256.Size]byte{} && gdme.AnchoredTimestamp == 0 {
				// Lazyflush record if it was anchored but blockchain timestamp
				// isn't avialable yet
				fr := backend.FlushRecord{
					Tx:   gdme.Tx,
					Root: gdme.MerkleRoot,
				}
				_, err = pg.lazyFlush(&fr)
				if err != nil {
					switch err {
					case errNotEnoughConfirmation:
						// All good, continue without blockchain timestamp
					case errInvalidConfirmations:
						log.Errorf("%v: Confirmations = -1",
							gdme.Tx.String())
						return nil, err
					default:
						return nil, err
					}
				}
				gdme.AnchoredTimestamp = fr.ChainTimestamp
			}
		}
		gdmes = append(gdmes, gdme)
	}
	return gdmes, nil
}

// Return all hashes for given timestamps.
func (pg *Postgres) GetTimestamps([]int64) ([]backend.TimestampResult, error) {
	return nil, nil
}

// Store hashes and return timestamp and associated errors.  Put is
// allowed to return transient errors.
func (pg *Postgres) Put(hashes [][sha256.Size]byte) (int64, []backend.PutResult, error) {
	// Two-phase commit.
	pg.Lock()
	commit := pg.commit
	pg.Unlock()

	// Get current time rounded down.
	ts := pg.now().Unix()

	// Prep return and unwind bits before taking mutex.
	me := make([]backend.PutResult, 0, len(hashes))

	// Create batch transaction
	txn, err := pg.db.Begin()
	if err != nil {
		return 0, []backend.PutResult{}, err
	}

	stmt, err := txn.Prepare(pq.CopyIn("records", "digest",
		"collection_timestamp"))
	if err != nil {
		return 0, []backend.PutResult{}, err
	}

	for _, hash := range hashes {
		// Check if digest exists
		exists, err := pg.checkIfDigestExists(hash[:])
		if err != nil {
			return 0, []backend.PutResult{}, err
		}
		if exists {
			me = append(me, backend.PutResult{
				Digest:    hash,
				ErrorCode: backend.ErrorExists,
			})

			// Override error code during testing
			if pg.testing {
				me[len(me)-1].ErrorCode = digestFound
			}
			continue
		}
		// Insert record
		_, err = stmt.Exec(hash[:], ts)
		if err != nil {
			return 0, []backend.PutResult{}, err
		}

		// Mark as successful
		me = append(me, backend.PutResult{
			Digest:    hash,
			ErrorCode: backend.ErrorOK,
		})
	}

	// From this point on the operation must be atomic.
	pg.Lock()
	defer pg.Unlock()

	// Make sure we are on the same commit.
	if commit != pg.commit {
		return 0, []backend.PutResult{}, backend.ErrTryAgainLater
	}

	// Write to db
	_, err = stmt.Exec()
	if err != nil {
		return 0, []backend.PutResult{}, err
	}
	err = stmt.Close()
	if err != nil {
		return 0, []backend.PutResult{}, err
	}
	err = txn.Commit()
	if err != nil {
		return 0, []backend.PutResult{}, err
	}

	return ts, me, nil
}

// Close performs cleanup of the backend. In our case closes postgres
// connection
func (pg *Postgres) Close() {
	// Block until last command is complete.
	pg.Lock()
	defer pg.Unlock()
	defer log.Infof("Exiting")

	// We need nil tests when in dump/restore mode.
	if pg.cron != nil {
		pg.cron.Stop()
	}
	if pg.wallet != nil {
		pg.wallet.Close()
	}
	pg.db.Close()
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
	result, err := pg.wallet.GetWalletBalance()
	if err != nil {
		return nil, err
	}
	return &backend.GetBalanceResult{
		Total:       result.Total,
		Spendable:   result.Spendable,
		Unconfirmed: result.Unconfirmed,
	}, nil
}

// LastAnchor retrieves last successful anchor details
func (pg *Postgres) LastAnchor() (*backend.LastAnchorResult, error) {
	return nil, nil
}

func buildQueryString(rootCert, cert, key string) string {
	v := url.Values{}
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslcert", filepath.Join(cert))
	v.Set("sslkey", filepath.Join(key))
	return v.Encode()
}

// internalNew creates the Pstgres context but does not launch background
// bits.  This is used by the test packages.
func internalNew(host, net, rootCert, cert, key string) (*Postgres, error) {
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
		cron:     cron.New(),
		db:       db,
		duration: duration,
		myNow:    time.Now,
	}

	// Create tables
	err = pg.createTables()
	if err != nil {
		return nil, err
	}

	return pg, nil
}

// doFlush gets all timestamps which have unflushed records and flushes them.
// It skips current timestamp.
// It returns the number of timestamps that were flushed.
//
// This must be called with the WRITE lock held.  We may have to consider
// errors out of this function terminal.
func (pg *Postgres) doFlush() (int, error) {
	current := pg.now().Unix()

	// Get timestamps with unflushed records.
	// Exclude current timestamp.
	tss, err := pg.getUnflushedTimestamps(current)
	if err != nil {
		return 0, err
	}
	count := 0
	// Flush timestamps' records
	for _, ts := range tss {
		err = pg.flush(ts)
		if err != nil {
			e := fmt.Sprintf("flush %v: %v", ts, err)
			if pg.testing {
				panic(e)
			}
			log.Error(e)
		} else {
			count++
		}
	}

	return count, nil
}

// flusher is called periodically to flush the current timestamp.
func (pg *Postgres) flusher() {
	// From this point on the operation must be atomic.
	pg.Lock()
	defer pg.Unlock()
	start := time.Now()
	count, err := pg.doFlush()
	end := time.Since(start)
	if err != nil {
		log.Errorf("flusher: %v", err)
	}

	log.Infof("Flusher: timestamps %v in %v", count, end)
}

// flush flushes all records associated with given timestamp.
// returns nil iff ts records flushed successfully
//
// This function must be called with the WRITE lock held
func (pg *Postgres) flush(ts int64) error {
	// Get timestamp's digests
	digests, err := pg.getDigestsByTimestamp(ts)
	if err != nil {
		return err
	}

	if len(digests) == 0 {
		// This really should not happen
		return errEmptySet
	}

	// Generate merkle
	mt := merkle.Tree(digests)
	// Last element is root
	root := *mt[len(mt)-1]
	fr := backend.FlushRecord{
		Root:           root,
		Hashes:         mt[:len(digests)], // Only store hashes
		FlushTimestamp: time.Now().Unix(),
	}
	if !pg.testing {
		tx, err := pg.wallet.Construct(root)
		if err != nil {
			// XXX do something with unsufficient funds here.
			return fmt.Errorf("flush Construct tx: %v", err)
		}
		log.Infof("Flush timestamp: %v digests %v merkle: %x tx: %v",
			ts, len(digests), root, tx.String())
		fr.Tx = *tx
	}

	// Insert anchor data into db
	err = pg.insertAnchor(fr)
	if err != nil {
		return err
	}

	// Update timestamp's records merkle root
	pg.updateRecordsAnchor(ts, fr.Root)

	// Update commit.
	pg.commit++

	return nil
}

// New creates a new backend instance.  The caller should issue a Close once
// the Postgres backend is no longer needed.
func New(host, net, rootCert, cert, key, walletCert, walletHost string, enableCollections bool, walletPassphrase []byte) (*Postgres, error) {
	log.Tracef("New: %v %v %v %v %v", host, net, rootCert, cert, key)

	pg, err := internalNew(host, net, rootCert, cert, key)
	if err != nil {
		return nil, err
	}
	pg.enableCollections = enableCollections

	// Runtime bits
	dcrtimewallet.UseLogger(log)
	pg.wallet, err = dcrtimewallet.New(walletCert, walletHost, walletPassphrase)
	if err != nil {
		return nil, err
	}

	// Flushing backend reconciles uncommitted work to the anchors table.
	start := time.Now()
	flushed, err := pg.doFlush()
	end := time.Since(start)
	if err != nil {
		return nil, err
	}

	if flushed != 0 {
		log.Infof("Startup flusher: timestamps %v in %v", flushed, end)
	}

	// Launch cron.
	err = pg.cron.AddFunc(flushSchedule, func() {
		pg.flusher()
	})
	if err != nil {
		return nil, err
	}

	pg.cron.Start()

	return pg, nil

}
