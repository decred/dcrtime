// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/dcrtimewallet"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/robfig/cron"
)

const (
	fStr         = "20060102.150405"
	tableRecords = "records"
	tableAnchors = "anchors"

	// errorFound is thrown if digest was found in records table
	errorFound = 1001
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

// Return timestamp information for given digests.
func (pg *Postgres) Get([][sha256.Size]byte) ([]backend.GetResult, error) {
	return nil, nil
}

// Return all hashes for given timestamps.
func (pg *Postgres) GetTimestamps([]int64) ([]backend.TimestampResult, error) {
	return nil, nil
}

func (pg *Postgres) checkIfDigestExists(hash []byte) (bool, error) {
	rows, err := pg.db.Query(`SELECT EXISTS (SELECT FROM records 
		WHERE digest = $1)`, hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var exists bool
	for rows.Next() {
		err = rows.Scan(&exists)
		if err != nil {
			return false, err
		}
	}
	return exists, nil
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
				me[len(me)-1].ErrorCode = errorFound
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

func buildQueryString(rootCert, cert, key string) string {
	v := url.Values{}
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslcert", filepath.Join(cert))
	v.Set("sslkey", filepath.Join(key))
	return v.Encode()
}

func hasTable(db *sql.DB, name string) (bool, error) {
	rows, err := db.Query(`SELECT EXISTS (SELECT FROM information_schema.tables 
		WHERE table_schema = 'public' AND table_name  = $1)`, name)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var exists bool
	for rows.Next() {
		err = rows.Scan(&exists)
		if err != nil {
			return false, err
		}
	}
	return exists, nil
}

func createAnchorsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE public.anchors
(
    merkle character varying(64) COLLATE pg_catalog."default" NOT NULL,
    hashes text[] COLLATE pg_catalog."default" NOT NULL,
    tx_hash text COLLATE pg_catalog."default",
    chain_timestamp bigint,
    flush_timestamp bigint,
    CONSTRAINT anchors_pkey PRIMARY KEY (merkle)
);
-- Index: idx_chain_timestamp
CREATE INDEX idx_chain_timestamp
    ON public.anchors USING btree
    (chain_timestamp ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_flush_timestamp
CREATE INDEX idx_flush_timestamp
    ON public.anchors USING btree
    (flush_timestamp ASC NULLS LAST)
    TABLESPACE pg_default;
`)
	if err != nil {
		return err
	}
	log.Infof("Anchors table created")
	return nil
}

func createRecordsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE public.records
(
    digest bytea NOT NULL,
    anchor_merkle character varying(64) COLLATE pg_catalog."default",
    key serial NOT NULL,
    collection_timestamp text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT records_pkey PRIMARY KEY (key),
    CONSTRAINT records_anchors_fkey FOREIGN KEY (anchor_merkle)
        REFERENCES public.anchors (merkle) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
);

-- Index: fki_records_anchors_fkey
CREATE INDEX fki_records_anchors_fkey
    ON public.records USING btree
    (anchor_merkle COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;

-- Index: idx_collection_timestamp
CREATE INDEX idx_collection_timestamp
    ON public.records USING btree
    (collection_timestamp COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
`)
	if err != nil {
		return err
	}
	log.Infof("Records table created")
	return nil
}

func createTables(db *sql.DB) error {
	exists, err := hasTable(db, tableAnchors)
	if err != nil {
		return err
	}
	if !exists {
		err = createAnchorsTable(db)
		if err != nil {
			return err
		}
	}
	exists, err = hasTable(db, tableRecords)
	if err != nil {
		return err
	}
	if !exists {
		err = createRecordsTable(db)
		if err != nil {
			return err
		}
	}
	return nil
}

// internalNew creates the Pstgres context but does not launch background
// bits.  This is used by the test packages.
func internalNew(user, host, net, rootCert, cert, key string) (*Postgres, error) {
	// Connect to database
	dbName := net + "_dcrtime"
	h := "postgresql://" + user + "@" + host + "/" + dbName
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

	// Create tables
	err = createTables(db)
	if err != nil {
		return nil, err
	}

	pg := &Postgres{
		cron:     cron.New(),
		db:       db,
		duration: duration,
		myNow:    time.Now,
	}

	return pg, nil
}

// New creates a new backend instance.  The caller should issue a Close once
// the Postgres backend is no longer needed.
func New(user, host, net, rootCert, cert, key, walletCert, walletHost string, enableCollections bool, walletPassphrase []byte) (*Postgres, error) {
	// XXX log more stuff
	log.Tracef("New: %v %v %v %v %v %v", user, host, net, rootCert, cert, key)

	pg, err := internalNew(user, host, net, rootCert, cert, key)
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

	// Flushing backend reconciles uncommitted work to the global database.
	//start := time.Now()
	//flushed, err := pg.doFlush()
	//end := time.Since(start)
	//if err != nil {
	//return nil, err
	//}

	//if flushed != 0 {
	//log.Infof("Startup flusher: directories %v in %v", flushed, end)
	//}

	// Launch cron.
	err = pg.cron.AddFunc(flushSchedule, func() {
	})
	if err != nil {
		return nil, err
	}

	pg.cron.Start()

	return pg, nil
}
