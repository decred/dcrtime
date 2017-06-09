// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/dcrtimewallet"
	"github.com/decred/dcrtime/merkle"
	"github.com/robfig/cron"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	fStr          = "20060102.150405"
	globalDBDir   = "global"
	flushedKey    = "flushed"
	confirmations = 6

	// error codes that are overridden during tests only.
	foundGlobal = 1000
	foundLocal  = 1001
)

var (
	_ backend.Backend = (*FileSystem)(nil)

	// duration and flushSchedule must match or bad things will happen.  By
	// matching we mean both are hourly or every so many minutes.  This
	// really should be automated but cron is hard.
	//
	// Seconds Minutes Hours Days Months DayOfWeek
	flushSchedule = "10 0 * * * *" // On the hour + 10 seconds
	duration      = time.Hour      // Default how often we combine digests

	// Errors
	errInvalidDB      = errors.New("not a database") // Should not happen
	errAlreadyFlushed = errors.New("already flushed")
	errEmptySet       = errors.New("empty set")
)

// FileSystem is a naive implementation of a backend.  It uses rounded
// timestamps as an index directory which then contains a leveldb with the
// content.  There is also a global leveldb that provides a reverse index.
type FileSystem struct {
	sync.RWMutex

	cron     *cron.Cron    // Scheduler for periodic tasks
	root     string        // Root directory
	db       *leveldb.DB   // Global database [hash]timestamp
	duration time.Duration // How often we combine digests
	commit   uint          // Current version, incremented during flush

	wallet *dcrtimewallet.DcrtimeWallet // Wallet context.

	// testing only entries
	myNow   func() time.Time // Override time.Now()
	testing bool             // Enabled during test
}

// ts2dirname converts a UNIX timestamp to a human readable timestamp.
func ts2dirname(ts int64) string {
	return time.Unix(ts, 0).UTC().Format(fStr)
}

func EncodeFlushRecord(fr backend.FlushRecord) ([]byte, error) {
	b, err := json.Marshal(fr)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func DecodeFlushRecord(payload []byte) (*backend.FlushRecord, error) {
	var fr backend.FlushRecord

	err := json.Unmarshal(payload, &fr)
	if err != nil {
		return nil, err
	}

	return &fr, nil
}

// now returns current time stamp rounded down to 1 hour.  All timestamps are
// UTC.
func (fs *FileSystem) now() time.Time {
	return fs.truncate(fs.myNow().UTC(), fs.duration)
}

// truncate rounds time down to the provided duration.  This is split out in
// order to test.
func (fs *FileSystem) truncate(t time.Time, d time.Duration) time.Time {
	return t.Truncate(d)
}

// openRead tries to open the database associated with the provided timestamp.
// This function explicitely checks for a container directory in order to not
// create a database for a non existing timestamp.  The caller is responsible
// for closing the database.
func (fs *FileSystem) openRead(ts int64) (*leveldb.DB, error) {
	// Create path from timestamp.
	path := filepath.Join(fs.root, ts2dirname(ts))

	// Stat path first so that we don't create a database for a non
	// existing timestamp.  Leveldb WILL create a directory even if
	// ErrorIfMissing = true.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	if !fi.Mode().IsDir() {
		return nil, errInvalidDB
	}

	// Try opening database.
	db, err := leveldb.OpenFile(path, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// openWrite tries to open the database associated with the provided timestamp
// for writes.  The function will create the container directoryf create is set
// to true.  The caller is responsible for closing the database.
func (fs *FileSystem) openWrite(ts int64, create bool) (*leveldb.DB, error) {
	// Always create container.
	path := filepath.Join(fs.root, ts2dirname(ts))
	err := os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	// Open/create timestamp database
	db, err := leveldb.OpenFile(path, &opt.Options{
		ErrorIfMissing: !create,
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// isFlushed returns true if the provided db has been flushed.
func isFlushed(db *leveldb.DB) bool {
	found, _ := db.Has([]byte(flushedKey), nil)
	return found
}

// isFlushed returns true if the provided timestamp has been flushed.
func (fs *FileSystem) isFlushed(ts int64) bool {
	db, err := fs.openRead(ts)
	if err != nil {
		return false
	}
	defer db.Close()

	return isFlushed(db)
}

// flush moves provided timestamp container into global database.
//
// This function must be called with the WRITE lock held.
func (fs *FileSystem) flush(ts int64) ([]*[sha256.Size]byte, error) {
	// Open timestamp container.
	db, err := fs.openWrite(ts, false)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Error if we are already flushed
	if isFlushed(db) {
		return nil, errAlreadyFlushed
	}

	hashes := make([]*[sha256.Size]byte, 0, 4096)

	// Iterate over timestamp container and create batch for global
	// database.
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(ts))
	files := 0
	batch := new(leveldb.Batch)
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		var digest [sha256.Size]byte
		hash := iter.Key()
		batch.Put(hash, timestamp)
		copy(digest[:], hash)
		hashes = append(hashes, &digest)
		files++
	}
	iter.Release()
	err = iter.Error()
	if err != nil {
		return nil, err
	}

	if len(hashes) == 0 {
		// this really should not happen.
		return nil, errEmptySet
	}

	// Create merkle root and send to wallet
	mt := merkle.Tree(hashes)
	root := *mt[len(mt)-1] // Last element is root
	fr := backend.FlushRecord{
		Root:           root,
		Hashes:         mt[:len(hashes)], // Only store hashes
		FlushTimestamp: time.Now().Unix(),
	}
	if !fs.testing {
		tx, err := fs.wallet.Construct(root)
		if err != nil {
			// XXX do something with unsufficient funds here.
			return nil, fmt.Errorf("flush Construct tx: %v", err)
		}
		log.Infof("Flush timestamp: %v digests %v merkle: %x tx: %v",
			ts2dirname(ts), files, root, tx.String())
		fr.Tx = *tx
	}

	// Encode flush record.  We use JSON because it handles nil correctly.
	// Sorry!
	payload, err := EncodeFlushRecord(fr)
	if err != nil {
		return nil, err
	}

	// Commit to global database.
	err = fs.db.Write(batch, nil)
	if err != nil {
		return nil, err
	}

	// Mark timestamp container as flushed.
	err = db.Put([]byte(flushedKey), payload, nil)
	if err != nil {
		return nil, err
	}

	// Update commit.
	fs.commit++

	return hashes, nil
}

// doFlush walks timestamp directories backwards iand flushed them to the
// global database until it finds a flushed timestamp directory.  At that point
// the flusher exits.  It returns the number of directories that were flushed.
//
// This must be called with the WRITE lock held.  We may have to consider
// errors out of this function terminal.
func (fs *FileSystem) doFlush() (int, error) {
	now := fs.now().Format(fStr)

	// Get Dirs.
	files, err := ioutil.ReadDir(fs.root)
	if err != nil {
		return 0, err
	}

	// Create work.
	dirs := make([]string, 0, len(files))
	for _, file := range files {
		// Skip global db.
		if file.Name() == globalDBDir {
			continue
		}
		if !file.IsDir() {
			continue
		}
		// Skip current timestamp.
		if file.Name() == now {
			continue
		}

		dirs = append(dirs, file.Name())
	}

	// Reverse sort work.
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))

	// Walk directories backwards until we find a flushed database.  At
	// this point we know we are caught up.
	count := 0
	for _, dir := range dirs {
		// Skip invalid directories.
		timestamp, err := time.Parse(fStr, dir)
		if err != nil {
			continue
		}
		ts := timestamp.Unix()

		// Skip flushed dirs.
		if fs.isFlushed(ts) {
			// We hit a flushed dir so we should be done.
			break
		}

		// Flush timestamp container
		_, err = fs.flush(ts)
		if err != nil {
			e := fmt.Sprintf("flush %v: %v", ts2dirname(ts), err)
			if fs.testing {
				panic(e)
			}
			log.Error(e)
		}

		count++
	}

	return count, nil
}

// flusher is called periodically to flush the current timestamp to disk.
func (fs *FileSystem) flusher() {
	// From this point on the operation must be atomic.
	fs.Lock()
	defer fs.Unlock()

	start := time.Now()
	count, err := fs.doFlush()
	end := time.Since(start)
	if err != nil {
		log.Errorf("flusher: %v", err)
	}

	log.Infof("Flusher: directories %v in %v", count, end)
}

var (
	errInvalidConfirmations  = errors.New("invalid confirmations")
	errNotEnoughConfirmation = errors.New("not enough confirmations")
)

// lazyFlush takes a pointer to a flush record and update the chain anchor
// timestamp of said record and writed is back to the database.
//
// IMPORTANT NOTE: We *may* write to a timestamp database in case of a lazy
// timestamp update to the flush record while holding the READ lock.  This is
// OK because at worst we are racing multiple atomic writes to the same key
// with the same information.  This is suboptimal but beats taking a write lock
// for all get* calls.
func (fs *FileSystem) lazyFlush(dbts int64, fr *backend.FlushRecord) error {
	res, err := fs.wallet.Lookup(fr.Tx)
	if err != nil {
		return err
	}

	log.Debugf("lazyFlush confirmations: %v", res.Confirmations)

	if res.Confirmations == -1 {
		return errInvalidConfirmations
	} else if res.Confirmations < confirmations {
		return errNotEnoughConfirmation
	}

	// Reassign and write back flush record
	fr.ChainTimestamp = res.Timestamp

	// Write back
	payload, err := EncodeFlushRecord(*fr)
	if err != nil {
		return err
	}
	dbw, err := fs.openWrite(dbts, false)
	if err != nil {
		return err
	}
	defer dbw.Close()
	err = dbw.Put([]byte(flushedKey), payload, nil)
	if err != nil {
		return err
	}

	log.Infof("Flushed anchor timestamp: %v %v", fr.Tx.String(),
		res.Timestamp)

	return nil
}

// getTimestamp returns all hashes for a given timestamp.
//
// Must be called with the READ lock held.
func (fs *FileSystem) getTimestamp(timestamp int64) (backend.TimestampResult, error) {
	gtme := backend.TimestampResult{
		Timestamp: timestamp,
		ErrorCode: backend.ErrorNotFound,
	}

	// Try opening database.
	db, err := fs.openRead(timestamp)
	if err != nil {
		if os.IsNotExist(err) {
			return gtme, nil
		}
		return gtme, err
	}

	// Check for flush record and use cached value instead of iterating
	// over all digest records.
	var fr *backend.FlushRecord
	payload, err := db.Get([]byte(flushedKey), nil)
	if err == nil {
		db.Close() // Close db because we may write back to it.

		fr, err = DecodeFlushRecord(payload)
		if err != nil {
			return gtme, err
		}

		gtme.ErrorCode = backend.ErrorOK
		gtme.Tx = fr.Tx
		gtme.MerkleRoot = fr.Root

		// Convert pointers
		gtme.Digests = make([][sha256.Size]byte, 0, len(fr.Hashes))
		for _, ph := range fr.Hashes {
			if ph == nil {
				continue
			}
			gtme.Digests = append(gtme.Digests, *ph)
		}

		// Do the lazy flush, note that fr.ChainTimestamp is updated.
		if fr.ChainTimestamp == 0 && !fs.testing {
			err = fs.lazyFlush(timestamp, fr)
			if err != nil {
				if err == errNotEnoughConfirmation {
					// fr.ChainTimestamp == 0
				} else if err == errInvalidConfirmations {
					log.Errorf("%v: Confirmations = -1",
						fr.Tx.String())
					return gtme, err
				} else {
					return gtme, err
				}
			}
		}

		gtme.AnchoredTimestamp = fr.ChainTimestamp

		return gtme, nil
	}

	defer db.Close()

	// Iterate over all hashes for given timestamp.
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		hash := iter.Key()
		// XXX this really needs to become a skip list.
		if bytes.Equal(hash, []byte(flushedKey)) {
			// In theory this can't happen so just return an error.
			return gtme, fmt.Errorf("impossible condition")
		}
		var h [sha256.Size]byte
		copy(h[:], hash)
		gtme.Digests = append(gtme.Digests, h)
	}
	iter.Release()
	err = iter.Error()
	if err != nil {
		return gtme, err
	}

	// Fill out missing bits
	gtme.ErrorCode = backend.ErrorOK

	return gtme, nil
}

// getDigest tries to return the timestamp information of the provided digest.
// It tries the global database and if that fails it tries the current
// timestamp database (it it exists).  This function must be called with the
// READ lock held.
func (fs *FileSystem) getDigest(ts int64, current *leveldb.DB, digest [sha256.Size]byte) (backend.GetResult, error) {
	gdme := backend.GetResult{
		Digest:    digest,
		Timestamp: ts,
	}

	// Lookup in global database if there are dups.
	gdbts, err := fs.db.Get(digest[:], nil)
	if err == nil {
		gdme.ErrorCode = backend.ErrorOK
		gdme.AnchoredTimestamp = 0
		dbts := int64(binary.LittleEndian.Uint64(gdbts))

		// Decode flushed record
		db, err := fs.openRead(dbts)
		if err != nil {
			return gdme, err
		}

		var fr *backend.FlushRecord
		payload, err := db.Get([]byte(flushedKey), nil)
		if err == nil {
			fr, err = DecodeFlushRecord(payload)
			if err != nil {
				return gdme, err
			}
			gdme.AnchoredTimestamp = fr.ChainTimestamp
			gdme.Tx = fr.Tx
			gdme.MerkleRoot = fr.Root
			// That pointer better not be nil!
			gdme.MerklePath = *merkle.AuthPath(fr.Hashes, &digest)
		}
		db.Close()

		// Override error code during testing
		if fs.testing {
			gdme.ErrorCode = foundGlobal
		} else if gdme.AnchoredTimestamp == 0 {
			err = fs.lazyFlush(dbts, fr)
			if err != nil {
				if err == errNotEnoughConfirmation {
					// fr.ChainTimestamp == 0
				} else if err == errInvalidConfirmations {
					log.Errorf("%v: Confirmations = -1",
						fr.Tx.String())
					return gdme, err
				} else {
					return gdme, err
				}
			}

			gdme.AnchoredTimestamp = fr.ChainTimestamp
		}

		return gdme, nil
	}

	// Lookup in current timestamp database, if it exists
	if current != nil {
		found, err := current.Has(digest[:], nil)
		if err != nil {
			return gdme, err
		}
		if found {
			gdme.ErrorCode = backend.ErrorOK
			gdme.AnchoredTimestamp = 0 // Not anchored if current

			// Override error code during testing
			if fs.testing {
				gdme.ErrorCode = foundLocal
			}
			return gdme, nil
		}
	}

	// Not found.
	gdme.ErrorCode = backend.ErrorNotFound

	return gdme, nil
}

// Get returns a GetResult for each provided digest.
//
// Get satisfies the backend interface.
func (fs *FileSystem) Get(digests [][sha256.Size]byte) ([]backend.GetResult, error) {
	gdmes := make([]backend.GetResult, 0, len(digests))

	// We need to be read locked from here on out.  Note that we are not
	// locking/releasing.  This is by design in order to let all readers
	// finish before a potential write occurs.
	fs.RLock()
	defer fs.RUnlock()

	// Get current time rounded down.
	ts := fs.now().Unix()

	// Open current timestamp database
	current, err := fs.openRead(ts)
	if err != nil {
		// Everything that isn't "doesn't exist" is a fatal error.
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		defer current.Close()
	}

	// Iterate over digests and translate results to backend interface.
	for _, d := range digests {
		gdme, err := fs.getDigest(ts, current, d)
		if err != nil {
			gdme = backend.GetResult{
				Digest:    d,
				ErrorCode: backend.ErrorOK,
			}
			if os.IsNotExist(err) {
				gdme.ErrorCode = backend.ErrorNotFound
			} else {
				return nil, err
			}
		}
		gdmes = append(gdmes, gdme)
	}

	return gdmes, nil
}

// GetTimestamps is a required interface function.  In our case it retrieves
// the digests for a given timestamp.
//
// GetTimestamps satisfies the backend interface.
func (fs *FileSystem) GetTimestamps(timestamps []int64) ([]backend.TimestampResult, error) {
	gtmes := make([]backend.TimestampResult, 0, len(timestamps))

	// We need to be read locked from here on out.  Note that we are not
	// locking/releasing.  This is by design in order to let all readers
	// finish before a potential write occurs.
	fs.RLock()
	defer fs.RUnlock()

	// Iterate over timestamps and translate results to backend interface.
	for _, ts := range timestamps {
		gtme, err := fs.getTimestamp(ts)
		if err != nil {
			gtme = backend.TimestampResult{
				Timestamp: ts,
				ErrorCode: backend.ErrorOK,
			}
			if os.IsNotExist(err) {
				gtme.ErrorCode = backend.ErrorNotFound
			} else {
				return nil, err
			}
		}
		gtmes = append(gtmes, gtme)
	}

	return gtmes, nil
}

// Put is a required interface function.  In our case it stores the provided
// hashes in a database that lives in a container directory.  The container
// directory is the current time in UTC rounded down to the last hour.
//
// Put satisfies the backend interface.
func (fs *FileSystem) Put(hashes [][sha256.Size]byte) (int64, []backend.PutResult, error) {
	// Poor mans two-phase commit.
	fs.Lock()
	commit := fs.commit
	fs.Unlock()

	// Get current time rounded down.
	ts := fs.now().Unix()
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, uint64(ts))

	// Prep return and unwind bits before taking mutex.
	me := make([]backend.PutResult, 0, len(hashes))

	// Open current timestamp database
	current, err := fs.openWrite(ts, true)
	if err != nil {
		return 0, me, err
	}
	defer current.Close()

	// Create a Put batch for provided digests.  Obviously looking things
	// up without a lock will make the lookups racy however when a
	// container is committed it is locked and therefore overall an atomic
	// operation.
	// We ignore duplicates in the same batch by simply overwriting them.
	batch := new(leveldb.Batch)
	for _, hash := range hashes {
		// Lookup in current timestamp database
		foundL, err := current.Has(hash[:], nil)
		if err != nil {
			return 0, []backend.PutResult{}, err
		}
		if foundL {
			me = append(me, backend.PutResult{
				Digest:    hash,
				ErrorCode: backend.ErrorExists,
			})

			// Override error code during testing
			if fs.testing {
				me[len(me)-1].ErrorCode = foundLocal
			}
			continue
		}

		// Lookup in global database if there are dups.
		foundG, err := fs.db.Has(hash[:], nil)
		if err != nil {
			return 0, []backend.PutResult{}, err
		}
		if foundG {
			me = append(me, backend.PutResult{
				Digest:    hash,
				ErrorCode: backend.ErrorExists,
			})

			// Override error code during testing
			if fs.testing {
				me[len(me)-1].ErrorCode = foundGlobal
			}
			continue
		}

		// Determine if we want to store some metadata.
		batch.Put(hash[:], timestamp)

		// Mark as successful.
		me = append(me, backend.PutResult{
			Digest:    hash,
			ErrorCode: backend.ErrorOK,
		})
	}

	// From this point on the operation must be atomic.
	fs.Lock()
	defer fs.Unlock()

	// Make sure we are on the same commit.
	if commit != fs.commit {
		return 0, []backend.PutResult{}, backend.ErrTryAgainLater
	}

	err = current.Write(batch, nil)
	if err != nil {
		return 0, []backend.PutResult{}, err
	}

	return ts, me, nil
}

// Close is a required interface function.  In our case we close the global
// database.
//
// Close satisfies the backend interface.
func (fs *FileSystem) Close() {
	// Block until last command is complete.
	fs.Lock()
	defer fs.Unlock()
	defer log.Infof("Exiting")

	fs.cron.Stop()
	fs.wallet.Close()
	fs.db.Close()
}

// internalNew creates the FileSystem context but does not launch background
// bits.  This is used by the test packages.
func internalNew(root string) (*FileSystem, error) {
	db, err := leveldb.OpenFile(filepath.Join(root, globalDBDir), nil)
	if err != nil {
		return nil, err
	}

	fs := &FileSystem{
		cron:     cron.New(),
		root:     root,
		db:       db,
		duration: duration,
		myNow:    func() time.Time { return time.Now() },
	}

	return fs, nil
}

// New creates a new backend instance.  The caller should issue a Close once
// the FileSystem backend is no longer needed.
func New(root, cert, host string, passphrase []byte) (*FileSystem, error) {
	fs, err := internalNew(root)
	if err != nil {
		return nil, err
	}

	// Runtime bits
	dcrtimewallet.UseLogger(log)
	fs.wallet, err = dcrtimewallet.New(cert, host, passphrase)
	if err != nil {
		return nil, err
	}

	// Flushing backend reconciles uncommited work to the global database.
	start := time.Now()
	flushed, err := fs.doFlush()
	end := time.Since(start)
	if err != nil {
		return nil, err
	}

	if flushed != 0 {
		log.Infof("Startup flusher: directories %v in %v", flushed, end)
	}

	// Launch cron.
	err = fs.cron.AddFunc(flushSchedule, func() {
		fs.flusher()
	})
	if err != nil {
		return nil, err
	}

	fs.cron.Start()

	return fs, nil
}
