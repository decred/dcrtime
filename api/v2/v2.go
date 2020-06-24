// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import (
	"fmt"
	"regexp"

	"github.com/decred/dcrtime/merkle"
)

type ResultT int

const (
	// APIVersion defines the version number for this code.
	APIVersion = 2

	// ResultInvalid indicates the operation on the backend was invalid.
	ResultInvalid ResultT = 0

	// ResultOK indicates the operation completed successfully.
	ResultOK ResultT = 1

	// ResultExistsError indicates the digest already exists and was
	// rejected.
	ResultExistsError ResultT = 2

	// ResultDoesntExistError indiciates the timestamp or digest does not
	// exist.
	ResultDoesntExistError ResultT = 3

	// ResultDisabled indicates querying is disabled.
	ResultDisabled ResultT = 4

	// DefaultMainnetTimeHost indicates the default mainnet time host
	// server.
	DefaultMainnetTimeHost = "time.decred.org"

	// DefaultMainnetTimePort indicates the default mainnet time host
	// port.
	DefaultMainnetTimePort = "49152"

	// DefaultTestnetTimeHost indicates the default testnet time host
	// server.
	DefaultTestnetTimeHost = "time-testnet.decred.org"

	// DefaultTestnetTimePort indicates the default testnet time host
	// port.
	DefaultTestnetTimePort = "59152"
)

var (
	// RoutePrefix is the route url prefix for this version.
	RoutePrefix = fmt.Sprintf("/v%v", APIVersion)

	// VersionRoute defines a top-level API route for retrieving latest version
	VersionRoute = "/version"

	// StatusRoute defines the API route for retrieving
	// the server status.
	StatusRoute = RoutePrefix + "/status"

	// TimestampRoute defines the API route for submitting
	// a single string digest, used by no-js clients.
	TimestampRoute = RoutePrefix + "/timestamp" // Single digest timestamping

	// VerifyRoute defines the API route for verifying
	// a single digest and timestamp, used by no-js clients.
	VerifyRoute = RoutePrefix + "/verify" // Single verify digest

	// TimestampBatchRoute defines the API route for submitting
	// a batch of timestamps or digests.
	TimestampBatchRoute = RoutePrefix + "/timestamp/batch" // Multi digest timestamping

	// VerifyBatchRoute defines the API route for both timestamp
	// and digest batch verification.
	VerifyBatchRoute = RoutePrefix + "/verify/batch" // Multi verify digests

	// WalletBalanceRoute defines the API route for retrieving
	// the account balance from dcrtimed's wallet instance
	WalletBalanceRoute = RoutePrefix + "/balance"

	// LastAnchorRoute defines the API route for retrieving
	// info about last successfull anchor, such as
	// timestamp, block height & tx id
	LastAnchorRoute = RoutePrefix + "/last"

	// Result defines legible string messages to a timestamping/query
	// result code.
	Result = map[ResultT]string{
		ResultInvalid:          "Invalid",
		ResultOK:               "OK",
		ResultExistsError:      "Exists",
		ResultDoesntExistError: "Doesn't exist",
		ResultDisabled:         "Query disallowed",
	}

	// RegexpSHA256 is the valid text representation of a sha256 digest.
	RegexpSHA256 = regexp.MustCompile("^[A-Fa-f0-9]{64}$")

	// RegexpTimestamp is the valid text representation of a timestamp.
	RegexpTimestamp = regexp.MustCompile("^[0-9]{10}$")
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

// VersionReply returns the version the server is currently running.
type VersionReply struct {
	Versions      []uint   `json:"versions"` // dcrtime API supported versions.
	RoutePrefixes []string `json:"routeprefixes"`
}

// Timestamp is used to ask the timestamp server to store a single digest.
// ID is user settable and can be used as a unique identifier by the client.
type Timestamp struct {
	ID     string `form:"id"`
	Digest string `form:"digest"`
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

// Verify is used to ask the server about the status of a single digest and/or
// timestamp.
type Verify struct {
	ID        string `form:"id"`
	Digest    string `form:"digest"`
	Timestamp int64  `form:"timestamp"`
}

// VerifyReply is returned by the server with the status results for the requested
// digest and/or timestamp.
type VerifyReply struct {
	ID        string          `json:"id"`
	Digest    VerifyDigest    `json:"digest"`
	Timestamp VerifyTimestamp `json:"timestamp"`
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

// TimestampBatch is used to ask the timestamp server to store a batch of digests.
// ID is user settable and can be used as a unique identifier by the client.
type TimestampBatch struct {
	ID      string   `json:"id"`
	Digests []string `json:"digests"`
}

// TimestampBatchReply is returned by the timestamp server after storing the batch
// of digests. ID is copied from the originating Timestamp call and can be
// used by the client as a unique identifier. The ServerTimestamp indicates
// what collection the Digests belong to. Results contains individual result
// codes for each digest.
type TimestampBatchReply struct {
	ID              string    `json:"id"`
	ServerTimestamp int64     `json:"servertimestamp"`
	Digests         []string  `json:"digests"`
	Results         []ResultT `json:"results"`
}

// VerifyBatch is used to ask the server about the status of a batch of digests or
// timestamps
type VerifyBatch struct {
	ID         string   `json:"id"`
	Digests    []string `json:"digests"`
	Timestamps []int64  `json:"timestamps"`
}

// VerifyBatchReply is returned by the server with the status results for the
// requested digests and timestamps.
type VerifyBatchReply struct {
	ID         string            `json:"id"`
	Digests    []VerifyDigest    `json:"digests"`
	Timestamps []VerifyTimestamp `json:"timestamps"`
}

// ChainInformation is returned by the server on a verify digest request.
// It contains the merkle path of that digest.
type ChainInformation struct {
	ChainTimestamp int64         `json:"chaintimestamp"`
	Transaction    string        `json:"transaction"`
	MerkleRoot     string        `json:"merkleroot"`
	MerklePath     merkle.Branch `json:"merklepath"`
}

// CollectionInformation is returned by the server on a verify timestamp
// request. It contains all digests grouped on the collection of the
// requested block timestamp.
type CollectionInformation struct {
	ChainTimestamp int64    `json:"chaintimestamp"`
	Transaction    string   `json:"transaction"`
	MerkleRoot     string   `json:"merkleroot"`
	Digests        []string `json:"digests"`
}

// WalletBalanceReply is returned by server on a balance information of the
// decred wallet.
type WalletBalanceReply struct {
	Total       int64 `json:"total"`
	Spendable   int64 `json:"spendable"`
	Unconfirmed int64 `json:"unconfirmed"`
}

// LastAnchorReply is returned by server on a last succcessful anchor info
// request, it includes the id of the latest successfully broadcasted tx,
// block hash & block height if the transaction was included in a block
// and the chain timestamp if the tx block has more than 6 confirmations.
type LastAnchorReply struct {
	ChainTimestamp int64  `json:"chaintimestamp"`
	Transaction    string `json:"transaction"`
	BlockHash      string `json:"blockhash"`
	BlockHeight    int32  `json:"blockheight"`
}
