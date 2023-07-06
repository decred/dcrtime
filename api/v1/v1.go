// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
	"regexp"

	"github.com/decred/dcrtime/merkle"
)

// XXX add a clamp to all batches

const (
	// APIVersion defines the version number for this code.
	APIVersion = 1

	// ResultOK indicates the operation completed successfully.
	ResultOK = 0

	// ResultExistsError indicates the digest already exists and was
	// rejected.
	ResultExistsError = 1

	// ResultDoesntExistError indiciates the timestamp or digest does not
	// exist.
	ResultDoesntExistError = 2

	// ResultDisabled indicates querying is disabled.
	ResultDisabled = 3

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

	// StatusRoute defines the API route for retrieving
	// the server status.
	StatusRoute = RoutePrefix + "/status/"

	// TimestampRoute defines the API route for submitting
	// both timestamps and digests.
	TimestampRoute = RoutePrefix + "/timestamp/"

	// VerifyRoute defines the API route for both timestamp
	// and digest verification.
	VerifyRoute = RoutePrefix + "/verify/" // Multi verify digest

	// WalletBalanceRoute defines the API route for retrieving
	// the account balance from dcrtimed's wallet instance
	WalletBalanceRoute = RoutePrefix + "/balance"

	// LastAnchorRoute defines the API route for retrieving
	// info about last successful anchor, such as
	// timestamp, block height & tx id
	LastAnchorRoute = RoutePrefix + "/last"

	// Result defines legible string messages to a timestamping/query
	// result code.
	Result = map[int]string{
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

// VerifyTimestamp is zero if this digest collection is not anchored in the
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
	ChainTimestamp int64         `json:"chaintimestamp"`
	Transaction    string        `json:"transaction"`
	MerkleRoot     string        `json:"merkleroot"`
	MerklePath     merkle.Branch `json:"merklepath"`
}

type CollectionInformation struct {
	ChainTimestamp int64    `json:"chaintimestamp"`
	Transaction    string   `json:"transaction"`
	MerkleRoot     string   `json:"merkleroot"`
	Digests        []string `json:"digests"`
}

type WalletBalanceReply struct {
	Total       int64 `json:"total"`
	Spendable   int64 `json:"spendable"`
	Unconfirmed int64 `json:"unconfirmed"`
}

type LastAnchorReply struct {
	ChainTimestamp int64  `json:"chaintimestamp"`
	Transaction    string `json:"transaction"`
	BlockHash      string `json:"blockhash"`
	BlockHeight    int32  `json:"blockheight"`
}
