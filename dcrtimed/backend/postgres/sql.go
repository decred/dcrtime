package postgres

import (
	"crypto/sha256"
	"database/sql"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/merkle"
)

func (pg *Postgres) getAllRecordsTimestamps() (*[]int64, error) {
	q := `SELECT collection_timestamp FROM records`

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

func (pg *Postgres) getLatestAnchoredTimestamp() (int64, *[sha256.Size]byte, *chainhash.Hash, error) {
	q := `SELECT r.collection_timestamp, r.anchor_merkle, an.tx_hash
				FROM records as r
				LEFT JOIN anchors as an
				on r.anchor_merkle = an.merkle
				WHERE r.anchor_merkle IS NOT NULL
				ORDER BY r.collection_timestamp DESC
				LIMIT 1`

	rows, err := pg.db.Query(q)
	if err != nil {
		return 0, nil, nil, err
	}
	defer rows.Close()

	var (
		serverTs   int64
		txHash, mr []byte
		merkle     [sha256.Size]byte
		tx         *chainhash.Hash
	)
	for rows.Next() {
		err = rows.Scan(&serverTs, &mr, &txHash)
		if err != nil {
			return 0, nil, nil, err
		}
		copy(merkle[:], mr[:sha256.Size])
		tx, err = chainhash.NewHash(txHash)
		if err != nil {
			return 0, nil, nil, err
		}
	}
	return serverTs, &merkle, tx, nil
}

func (pg *Postgres) updateAnchorChainTs(fr *backend.FlushRecord) error {
	q := `UPDATE anchors SET chain_timestamp = $1
				WHERE merkle = $2`

	err := pg.db.QueryRow(q, fr.ChainTimestamp, fr.Root[:]).Scan()
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

func (pg *Postgres) updateRecordsAnchor(ts int64, merkleRoot [sha256.Size]byte) error {
	q := `UPDATE records SET anchor_merkle = $1
				WHERE collection_timestamp = $2`

	err := pg.db.QueryRow(q, merkleRoot[:], ts).Scan()
	if err != nil {
		return err
	}
	return nil
}

func (pg *Postgres) insertAnchor(fr backend.FlushRecord) error {
	q := `INSERT INTO anchors (merkle, tx_hash, flush_timestamp)
				VALUES($1, $2, $3)`

	err := pg.db.QueryRow(q, fr.Root[:], fr.Tx[:],
		fr.FlushTimestamp).Scan()
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
	// Reverse hashes
	for i, j := 0, len(digests)-1; i < j; i, j = i+1, j-1 {
		digests[i], digests[j] = digests[j], digests[i]
	}
	return digests, nil
}

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

func (pg *Postgres) getRecordsByServerTs(ts int64) (bool, []*backend.GetResult, error) {
	q := `SELECT r.anchor_merkle, an.tx_hash, an.chain_timestamp, r.digest
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
	)
	r := []*backend.GetResult{}
	for rows.Next() {
		rr := backend.GetResult{
			Timestamp: ts,
		}
		err = rows.Scan(&mr, &txHash, &chainTs, &digest)
		if err != nil {
			return false, nil, err
		}
		rr.Timestamp = ts
		copy(rr.MerkleRoot[:], mr[:sha256.Size])
		tx, err := chainhash.NewHash(txHash[:])
		if err != nil {
			return false, nil, err
		}
		rr.Tx = *tx
		// chainTs can be NULL - handle safely
		if chainTs.Valid {
			rr.AnchoredTimestamp = chainTs.Int64
		}
		copy(rr.Digest[:], digest[:])

		r = append(r, &rr)
	}

	return len(r) > 0, r, nil
}

func (pg *Postgres) getRecordByDigest(hash []byte, r *backend.GetResult) (bool, error) {
	q := `SELECT r.anchor_merkle, r.collection_timestamp, an.tx_hash, 
				an.chain_timestamp
				FROM records as r
				LEFT JOIN anchors as an
				ON r.anchor_merkle = an.merkle
				WHERE r.digest = $1`

	rows, err := pg.db.Query(q, hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var (
		mr       []byte
		txHash   []byte
		chainTs  sql.NullInt64
		serverTs int64
	)
	for rows.Next() {
		err = rows.Scan(&mr, &serverTs, &txHash, &chainTs)
		if err != nil {
			return false, err
		}
		r.Timestamp = serverTs
		copy(r.MerkleRoot[:], mr[:sha256.Size])
		tx, err := chainhash.NewHash(txHash[:])
		if err != nil {
			return false, err
		}
		r.Tx = *tx
		// chainTs can be NULL - handle safely
		if chainTs.Valid {
			r.AnchoredTimestamp = chainTs.Int64
		}
		if mr != nil {
			hashes, err := pg.getDigestsByMerkleRoot(mr)
			if err != nil {
				return false, err
			}
			var digest [sha256.Size]byte
			copy(digest[:], hash[:])

			// That pointer better not be nil!
			r.MerklePath = *merkle.AuthPath(hashes, &digest)
		}
		r.ErrorCode = backend.ErrorOK
		return true, nil
	}

	return false, nil
}

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

func (pg *Postgres) checkIfDigestExists(hash []byte) (bool, error) {
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
