// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"regexp"

	"github.com/decred/dcrtime/merkle"
)

// XXX add a clamp to all batches

const (
	TimestampRoute = "/v1/timestamp/" // Digests ingest
	VerifyRoute    = "/v1/verify/"    // Multi verify ingest

	// Result codes.
	ResultOK               = 0 // Operation completed successfully
	ResultExistsError      = 1 // Digest rejected because it exists
	ResultDoesntExistError = 2 // Unknown timestamp or digest
	ResultDisabled         = 3 // Querying is disallowed

	DefaultMainnetTimeHost = "time.decred.org"
	DefaultMainnetTimePort = "49152"
	DefaultTestnetTimeHost = "time-testnet.decred.org"
	DefaultTestnetTimePort = "59152"
)

var (
	Result = map[int]string{
		ResultOK:               "OK",
		ResultExistsError:      "Exists",
		ResultDoesntExistError: "Doesn't exist",
		ResultDisabled:         "Query disallowed",
	}

	// Valid text representation of digests and timestamps.
	RegexpSHA256    = regexp.MustCompile("[A-Fa-f0-9]{64}")
	RegexpTimestamp = regexp.MustCompile("[0-9]{10}")
)

// Timestamp is used to ask the timestamp server to store a batch of digests.
// ID is user settable and can be used as a unique identifier by the client.
type Timestamp struct {
	ID      string   `json:"id"`
	Digests []string `json:"digests"`
}

// TimestampReply is returned by the timestamp server after storing the batch
// of digests.  ID is copied from the originating Timestamp call and can be
// used by the client as a unique identifier.  The ServerTimestamp indicates
// what collection the Digests belong to.  Results contains individual result
// codes for each digest.
type TimestampReply struct {
	ID              string   `json:"id"`
	ServerTimestamp int64    `json:"servertimestamp"`
	Digests         []string `json:"digests"`
	Results         []int    `json:"results"`
}

type Verify struct {
	ID         string   `json:"id"`
	Digests    []string `json:"digests"`
	Timestamps []int64  `json:"timestamps"`
}

type VerifyDigest struct {
	Digest           string           `json:"digest"`
	ServerTimestamp  int64            `json:"servertimestamp"`
	Result           int              `json:"result"`
	ChainInformation ChainInformation `json:"chaininformation"`
}

// ChainTimestamp is zero if this digest collection is not anchored in the
// blockchain; it is however set to the block timestamp it was anchored in.
type VerifyTimestamp struct {
	ServerTimestamp       int64                 `json:"servertimestamp"`
	Result                int                   `json:"result"`
	CollectionInformation CollectionInformation `json:"collectioninformation"`
}

type VerifyReply struct {
	ID         string            `json:"id"`
	Digests    []VerifyDigest    `json:"digests"`
	Timestamps []VerifyTimestamp `json:"timestamps"`
}

type ChainInformation struct {
	ChainTimestamp int64               `json:"chaintimestamp"`
	Transaction    string              `json:"transaction"`
	MerkleRoot     string              `json:"merkleroot"`
	MerklePath     merkle.MerkleBranch `json:"merklepath"`
}

type CollectionInformation struct {
	ChainTimestamp int64    `json:"chaintimestamp"`
	Transaction    string   `json:"transaction"`
	MerkleRoot     string   `json:"merkleroot"`
	Digests        []string `json:"digests"`
}
