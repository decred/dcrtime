// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import (
	"github.com/decred/dcrtime/merkle"
)

type ResultT int

const (
	// StatusRoute defines the API route for retrieving
	// the server status.
	StatusRoute = "/v2/status/"

	// TimestampRoute defines the API route for submitting
	// a single string digest.
	TimestampRoute = "/v2/timestamp/" // Single digest timestamping

	// TimestampsRoute defines the API route for submitting
	// a batch of timestamps or digests.
	TimestampsRoute = "/v2/timestamps/" // Multi digest timestamping

	// VerifyRoute defines the API route for both timestamp
	// and digest verification.
	VerifyRoute = "/v2/verify/" // Multi verify digests

	// ResultOK indicates the operation completed successfully.
	ResultOK ResultT = 0

	// ResultExistsError indicates the digest already exists and was
	// rejected.
	ResultExistsError ResultT = 1

	// ResultDoesntExistError indiciates the timestamp or digest does not
	// exist.
	ResultDoesntExistError ResultT = 2

	// ResultDisabled indicates querying is disabled.
	ResultDisabled ResultT = 3
)

var (
	// Result is a map of possible http results
	Result = map[ResultT]string{
		ResultOK:               "OK",
		ResultExistsError:      "Exists",
		ResultDoesntExistError: "Doesn't exist",
		ResultDisabled:         "Query disallowed",
	}
)

// Status is used to ask the server if everything is running properly.
// ID is user settable and can be used as a unique identifier by the client.
type Status struct {
	ID string `json:"id"`
}

// StatusReply is returned by the server if everything is running properly.
type StatusReply struct {
	ID string `json:"id"`
}

// Timestamp is used to ask the timestamp server to store a single digest.
// ID is user settable and can be used as a unique identifier by the client.
type Timestamp struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// TimestampReply is returned by the timestamp server after storing a single
// digest. ID is copied from the originating Timestamp call and can be
// used by the client as a unique identifier. ServerTimestamp indicates what
// collection the Digest belongs to. Result holds the result code for the digest.
type TimestampReply struct {
	ID              string  `json:"id"`
	ServerTimestamp int64   `json:"servertimestamp"`
	Digest          string  `json:"digest"`
	Result          ResultT `json:"result"`
}

// Timestamps is used to ask the timestamp server to store a batch of digests.
// ID is user settable and can be used as a unique identifier by the client.
type Timestamps struct {
	ID      string   `json:"id"`
	Digests []string `json:"digests"`
}

// TimestampsReply is returned by the timestamp server after storing the batch
// of digests. ID is copied from the originating Timestamp call and can be
// used by the client as a unique identifier. The ServerTimestamp indicates
// what collection the Digests belong to. Results contains individual result
// codes for each digest.
type TimestampsReply struct {
	ID              string    `json:"id"`
	ServerTimestamp int64     `json:"servertimestamp"`
	Digests         []string  `json:"digests"`
	Results         []ResultT `json:"results"`
}

// Verify is used to ask the server about the status of a batch of digests or
// timestamps
type Verify struct {
	ID         string   `json:"id"`
	Digests    []string `json:"digests"`
	Timestamps []int64  `json:"timestamps"`
}

// VerifyDigest is returned by the server after verifying the status of a
// digest.
type VerifyDigest struct {
	Digest           string           `json:"digest"`
	ServerTimestamp  int64            `json:"servertimestamp"`
	Result           ResultT          `json:"result"`
	ChainInformation ChainInformation `json:"chaininformation"`
}

// VerifyTimestamp is zero if this digest collection is not anchored in the
// blockchain; it is however set to the block timestamp it was anchored in.
type VerifyTimestamp struct {
	ServerTimestamp       int64                 `json:"servertimestamp"`
	Result                ResultT               `json:"result"`
	CollectionInformation CollectionInformation `json:"collectioninformation"`
}

// VerifyReply is returned by the server with the status results for the requested
// digests and timestamps.
type VerifyReply struct {
	ID         string            `json:"id"`
	Digests    []VerifyDigest    `json:"digests"`
	Timestamps []VerifyTimestamp `json:"timestamps"`
}

// ChainInformation is returned by the server on a verify digest request. It contains
// the merkle path of that digest.
type ChainInformation struct {
	ChainTimestamp int64         `json:"chaintimestamp"`
	Transaction    string        `json:"transaction"`
	MerkleRoot     string        `json:"merkleroot"`
	MerklePath     merkle.Branch `json:"merklepath"`
}

// CollectionInformation is returned by the server on a verify timestamp request.
// It contains all digests grouped on the collection of the requested block timestamp.
type CollectionInformation struct {
	ChainTimestamp int64    `json:"chaintimestamp"`
	Transaction    string   `json:"transaction"`
	MerkleRoot     string   `json:"merkleroot"`
	Digests        []string `json:"digests"`
}
