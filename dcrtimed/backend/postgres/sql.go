package postgres

import (
	"bytes"
	"crypto/sha256"
	"database/sql"

	"github.com/decred/dcrtime/merkle"
)

// insertRestoredDigest accepts a Record model and inserts it to the db
//
// this func used when restoring a backup
func (pg *Postgres) insertRestoredDigest(r Record) error {
	q := `INSERT INTO records (collection_timestamp, digest, anchor_merkle)
				VALUES($1, $2, $3)`

	err := pg.db.QueryRow(q, r.CollectionTimestamp, r.Digest, r.AnchorMerkle).Scan()
	if err != nil {
		// The insert command won't return any value, the following error is
		// expected and means anchor row inserted successfully
		if err.Error() == "sql: no rows in result set" {
			return nil
		}
		return err
	}
	return nil
}

// getAllRecordsTimestamps returns all timestamps found in records table
func (pg *Postgres) getAllRecordsTimestamps() (*[]int64, error) {
	q := `SELECT DISTINCT collection_timestamp FROM records`

	rows, err := pg.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tss []int64
	var ts int64
	for rows.Next() {
		err = rows.Scan(&ts)
		if err != nil {
			return nil, err
		}
		tss = append(tss, ts)
	}
	return &tss, nil
}

// getLatestAnchoredTimestamp returns latest anchor information - tx hash and
// merkle root, additionally it returns anchor's collection timestamp
func (pg *Postgres) getLatestAnchoredTimestamp() (int64, Anchor, error) {
	q := `SELECT r.collection_timestamp, r.anchor_merkle, an.tx_hash
				FROM records as r
				LEFT JOIN anchors as an
				on r.anchor_merkle = an.merkle
				WHERE r.anchor_merkle IS NOT NULL
				ORDER BY r.collection_timestamp DESC
				LIMIT 1`

	rows, err := pg.db.Query(q)
	a := Anchor{}
	if err != nil {
		return 0, a, err
	}
	defer rows.Close()

	var (
		serverTs   int64
		txHash, mr []byte
	)
	for rows.Next() {
		err = rows.Scan(&serverTs, &mr, &txHash)
		if err != nil {
			return 0, a, err
		}
		a.Merkle = mr
		a.TxHash = txHash
	}
	return serverTs, a, nil
}

// updateAnchorChainTs accepts an anchor and updates it's chain timestamp
// on db
func (pg *Postgres) updateAnchorChainTs(a Anchor) error {
	q := `UPDATE anchors SET chain_timestamp = $1
				WHERE merkle = $2`

	err := pg.db.QueryRow(q, a.ChainTimestamp, a.Merkle).Scan()
	if err != nil {
		// The update command won't return any value, the following error is
		// expected and means anchor row updated successfully
		if err.Error() == "sql: no rows in result set" {
			return nil
		}
		return err
	}
	return nil
}

// updateRecordsAnchor accepts a timestamp and anchor's merkle root and
// updates all digests in records table with given merkle
func (pg *Postgres) updateRecordsAnchor(ts int64, merkleRoot []byte) error {
	q := `UPDATE records SET anchor_merkle = $1
				WHERE collection_timestamp = $2`

	err := pg.db.QueryRow(q, merkleRoot, ts).Scan()
	if err != nil {
		return err
	}
	return nil
}

// insertAnchor accepts an anchor and inserts it to db
func (pg *Postgres) insertAnchor(a Anchor) error {
	q := `INSERT INTO anchors (merkle, tx_hash, flush_timestamp, chain_timestamp)
				VALUES($1, $2, $3, $4)`

	err := pg.db.QueryRow(q, a.Merkle, a.TxHash,
		a.FlushTimestamp, a.ChainTimestamp).Scan()
	if err != nil {
		// The insert command won't return any value, the following error is
		// expected and means anchor row inserted successfully
		if err.Error() == "sql: no rows in result set" {
			return nil
		}
		return err
	}
	return nil
}

// getDigestsByMerkleRoot accepts a merkle root, selects all digests from
// records table using given merkle, converts them to arrays([sha256.Size])
// and then finally returns the result as array of pointers
func (pg *Postgres) getDigestsByMerkleRoot(merkle []byte) ([]*[sha256.Size]byte, error) {
	q := `SELECT digest from records WHERE anchor_merkle = $1`

	rows, err := pg.db.Query(q, merkle)
	if err != nil {
		return nil, err
	}
	var digests []*[sha256.Size]byte
	for rows.Next() {
		var rawDigest []byte
		err = rows.Scan(&rawDigest)
		if err != nil {
			return nil, err
		}
		var digest [sha256.Size]byte
		copy(digest[:], rawDigest[:])
		digests = append(digests, &digest)
	}
	return digests, nil
}

// getDigestsByTimestamp accepts a timestamp, selects all digests from
// records table using given timestamp, converts them to arrays([sha256.Size])
// and then finally returns the result as array of pointers
func (pg *Postgres) getDigestsByTimestamp(ts int64) ([]*[sha256.Size]byte, error) {
	q := `SELECT digest from records WHERE collection_timestamp = $1`

	rows, err := pg.db.Query(q, ts)
	if err != nil {
		return nil, err
	}
	var digests []*[sha256.Size]byte
	for rows.Next() {
		var rawDigest []byte
		err = rows.Scan(&rawDigest)
		if err != nil {
			return nil, err
		}
		var digest [sha256.Size]byte
		copy(digest[:], rawDigest[:])
		digests = append(digests, &digest)
	}
	return digests, nil
}

// getUnflushedTimestamps accepts current server timestamp and queries records
// table to find all timestamps which aren't flushed yet - has no anchoring
// information
func (pg *Postgres) getUnflushedTimestamps(current int64) ([]int64, error) {
	q := `SELECT DISTINCT collection_timestamp FROM records 
				WHERE collection_timestamp != $1 AND anchor_merkle IS NULL`

	rows, err := pg.db.Query(q, current)
	if err != nil {
		return nil, err
	}
	var ts int64
	tss := []int64{}
	for rows.Next() {
		err = rows.Scan(&ts)
		if err != nil {
			return nil, err
		}
		tss = append(tss, ts)
	}
	return tss, nil
}

// getRecordsByServerTs accepts a server collection timestamps and returns
// all records timetamped during that timestamp cycle, additionally it returns
// the anchor information in case the timestamp's digests anchored on the
// blockchain
func (pg *Postgres) getRecordsByServerTs(ts int64) (bool, []*AnchoredRecord, error) {
	q := `SELECT r.anchor_merkle, an.tx_hash, an.chain_timestamp, r.digest,
        an.flush_timestamp
				FROM records as r
				LEFT JOIN anchors as an
				on r.anchor_merkle = an.merkle
				WHERE r.collection_timestamp = $1`

	rows, err := pg.db.Query(q, ts)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()
	var (
		mr      []byte
		digest  []byte
		txHash  []byte
		chainTs sql.NullInt64
		flushTs int64
	)
	r := []*AnchoredRecord{}
	for rows.Next() {
		ar := AnchoredRecord{
			Record: Record{
				CollectionTimestamp: ts,
			},
		}
		err = rows.Scan(&mr, &txHash, &chainTs, &digest, &flushTs)
		if err != nil {
			return false, nil, err
		}
		ar.Record.Digest = digest
		ar.Anchor = Anchor{
			Merkle:         mr,
			TxHash:         txHash,
			FlushTimestamp: flushTs,
		}
		// chainTs can be NULL - handle safely
		if chainTs.Valid {
			ar.Anchor.ChainTimestamp = chainTs.Int64
		}

		r = append(r, &ar)
	}

	return len(r) > 0, r, nil
}

// getRecordByDigest accepts apointer to an AnchoredRecord which initially
// includes only the record hash, it queries the db to get digest's data
// including anchor's data if hash is anchored, it returns a bool to indicate
// wether digest was found on db or not
func (pg *Postgres) getRecordByDigest(ar *AnchoredRecord) (bool, error) {
	q := `SELECT r.anchor_merkle, r.collection_timestamp, an.tx_hash, 
				an.chain_timestamp
				FROM records as r
				LEFT JOIN anchors as an
				ON r.anchor_merkle = an.merkle
				WHERE r.digest = $1`

	rows, err := pg.db.Query(q, ar.Record.Digest)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var chainTs sql.NullInt64
	for rows.Next() {
		err = rows.Scan(&ar.Anchor.Merkle, &ar.Record.CollectionTimestamp, &ar.Anchor.TxHash, &chainTs)
		if err != nil {
			return false, err
		}
		// chainTs can be NULL - handle safely
		if chainTs.Valid {
			ar.Anchor.ChainTimestamp = chainTs.Int64
		}
		if !bytes.Equal(ar.Anchor.Merkle, []byte{}) {
			hashes, err := pg.getDigestsByMerkleRoot(ar.Anchor.Merkle)
			if err != nil {
				return false, err
			}
			var digest [sha256.Size]byte
			copy(digest[:], ar.Record.Digest[:])

			// That pointer better not be nil!
			ar.MerklePath = *merkle.AuthPath(hashes, &digest)
		}
		return true, nil
	}

	return false, nil
}

// hasTable accepts a table name and checks if it was created
func (pg *Postgres) hasTable(name string) (bool, error) {
	q := `SELECT EXISTS (SELECT 
				FROM information_schema.tables 
				WHERE table_schema = 'public' AND table_name  = $1)`

	rows, err := pg.db.Query(q, name)
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

// isDigestExists accept a digest and checks if it's already exists in
// records table
func (pg *Postgres) isDigestExists(hash []byte) (bool, error) {
	q := `SELECT EXISTS 
			  (SELECT FROM records WHERE digest = $1)`

	rows, err := pg.db.Query(q, hash)
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

// createAnchorsTable creates anchors table
func (pg *Postgres) createAnchorsTable() error {
	_, err := pg.db.Exec(`CREATE TABLE public.anchors
(
    merkle bytea NOT NULL UNIQUE,
    tx_hash bytea UNIQUE,
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
-- Index: idx_merkle
CREATE UNIQUE INDEX idx_merkle
    ON public.anchors USING btree
		(merkle ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_tx_hash
CREATE UNIQUE INDEX idx_tx_hash
    ON public.anchors USING btree
    (tx_hash ASC NULLS LAST)
    TABLESPACE pg_default;
`)
	if err != nil {
		return err
	}
	log.Infof("Anchors table created")
	return nil
}

// createRecordsTable creates records table
func (pg *Postgres) createRecordsTable() error {
	_, err := pg.db.Exec(`CREATE TABLE public.records
(
    digest bytea NOT NULL UNIQUE,
    anchor_merkle bytea,
    collection_timestamp bigint NOT NULL,
    CONSTRAINT records_pkey PRIMARY KEY (digest),
    CONSTRAINT records_anchors_fkey FOREIGN KEY (anchor_merkle)
        REFERENCES public.anchors (merkle) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
);

-- Index: fki_records_anchors_fkey
CREATE INDEX fki_records_anchors_fkey
    ON public.records USING btree
    (anchor_merkle ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_collection_timestamp
CREATE INDEX idx_collection_timestamp
    ON public.records USING btree
    (collection_timestamp ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_digest
CREATE UNIQUE INDEX idx_digest
    ON public.records USING btree
    (digest ASC NULLS LAST)
    TABLESPACE pg_default;
`)
	if err != nil {
		return err
	}
	log.Infof("Records table created")
	return nil
}

// createsTables creates db tables needed for our postgres backend
// implementation
func (pg *Postgres) createTables() error {
	exists, err := pg.hasTable(tableAnchors)
	if err != nil {
		return err
	}
	if !exists {
		err = pg.createAnchorsTable()
		if err != nil {
			return err
		}
	}
	exists, err = pg.hasTable(tableRecords)
	if err != nil {
		return err
	}
	if !exists {
		err = pg.createRecordsTable()
		if err != nil {
			return err
		}
	}
	return nil
}
