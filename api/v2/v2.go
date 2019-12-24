// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

const (
	// StatusRoute behaves the same as /v1/status
	StatusRoute = "/v2/status/"

	// TimestampRoute defines the API route for submitting
	// a single string digest.
	TimestampRoute = "/v2/timestamp/"

	// TimestampsRoute behaves the same as /v1/timestamps
	TimestampsRoute = "/v2/timestamps/" // Multi digest timestamping

	// VerifyRoute behaves the same as /v2/verify
	VerifyRoute = "/v2/verify/" // Multi verify digests
)

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
	ID              string `json:"id"`
	ServerTimestamp int64  `json:"servertimestamp"`
	Digest          string `json:"digest"`
	Result          int    `json:"result"`
}
