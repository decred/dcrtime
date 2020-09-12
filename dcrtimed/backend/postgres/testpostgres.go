// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package postgres

import (
	"sync"
	"time"
)

// TestPostgres provides a implementation of the backend interface that stores
// records in memory and that can be used for testing.
type TestPostgres struct {
	sync.RWMutex

	commit uint // Current version, incremented during flush

	myNow func() time.Time // Override time.Now()

	// in memory data
	records []Record
	anchors []Anchor
}
