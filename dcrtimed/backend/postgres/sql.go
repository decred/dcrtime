package postgres

func (pg *Postgres) hasTable(name string) (bool, error) {
	rows, err := pg.db.Query(`SELECT EXISTS (SELECT FROM information_schema.tables 
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

func (pg *Postgres) createAnchorsTable() error {
	_, err := pg.db.Exec(`CREATE TABLE public.anchors
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
-- Index: idx_hashes
CREATE UNIQUE INDEX idx_hashes
    ON public.anchors USING btree
    (hashes COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_merkle
CREATE UNIQUE INDEX idx_merkle
    ON public.anchors USING btree
    (merkle COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_tx_hash
CREATE UNIQUE INDEX idx_tx_hash
    ON public.anchors USING btree
    (tx_hash COLLATE pg_catalog."default" ASC NULLS LAST)
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
    digest bytea NOT NULL,
    anchor_merkle character varying(64) COLLATE pg_catalog."default",
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
    (anchor_merkle COLLATE pg_catalog."default" ASC NULLS LAST)
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
