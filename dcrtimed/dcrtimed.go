// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	v1 "github.com/decred/dcrtime/api/v1"
	v2 "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
	"github.com/decred/dcrtime/util"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	fStr = "20060102.150405"

	forward = "X-Forwarded-For"
)

var (
	interruptSignals = []os.Signal{os.Interrupt}
)

// DcrtimeStore application context.
type DcrtimeStore struct {
	backend    backend.Backend
	cfg        *config
	router     *mux.Router
	ctx        context.Context
	httpClient *http.Client
	apiTokens  map[string]struct{}
}

func (d *DcrtimeStore) sendToBackend(ctx context.Context, w http.ResponseWriter,
	method, route, contentType, remoteAddr string, body *bytes.Reader) {

	storeHost := fmt.Sprintf("https://%s%s", d.cfg.StoreHost, route)
	req, err := http.NewRequestWithContext(ctx, method, storeHost, body)
	if err != nil {
		log.Errorf("Error generating new http request: %v", err)
		util.RespondWithError(w, http.StatusServiceUnavailable,
			"Server failed to generate a new http request")
		return
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set(forward, remoteAddr)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		log.Errorf("Error posting to storehost: %v", err)
		util.RespondWithError(w, http.StatusServiceUnavailable,
			"Server busy, please try again later.")
		return
	}

	defer resp.Body.Close()

	bodyBuf := new(bytes.Buffer)
	_, err = bodyBuf.ReadFrom(resp.Body)
	if err != nil {
		log.Errorf("ReadFrom failed: %v", err)
		util.RespondWithError(w, http.StatusServiceUnavailable,
			"Server busy, please try again later.")
		return
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			util.RespondWithCopy(w, http.StatusUnauthorized, "application/json",
				bodyBuf.Bytes())
			return
		}

		e, err := getError(resp.Body)
		if err != nil {
			log.Errorf("Bad status posting to %v: %v", storeHost,
				resp.Status)
		} else {
			log.Errorf("Bad status posting to %v: %v\n%v",
				storeHost, resp.Status, e)
		}

		util.RespondWithError(w, http.StatusInternalServerError,
			bodyBuf.String())
		return
	}
	err = util.RespondWithCopy(w, resp.StatusCode,
		resp.Header.Get("Content-Type"), bodyBuf.Bytes())
	if err != nil {
		log.Errorf("Error responding to client: %v", err)
	}
}

func (d *DcrtimeStore) proxyStatusV1(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var s v1.Status
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v1.StatusRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	log.Infof("%v Status %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyTimestampV1(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var t v1.Timestamp
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v1.TimestampRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	for _, v := range t.Digests {
		log.Infof("%v Timestamp %v: %v", r.URL.Path, r.RemoteAddr, v)
	}
}

func (d *DcrtimeStore) proxyVerifyV1(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var v v1.Verify
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v1.VerifyRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))
	log.Infof("%v Verify %v: Timestamps %v Digests %v",
		r.URL.Path, r.RemoteAddr, len(v.Timestamps), len(v.Digests))
}

func (d *DcrtimeStore) proxyWalletBalanceV1(w http.ResponseWriter, r *http.Request) {
	apiToken := r.URL.Query().Get("apitoken")
	route := v1.WalletBalanceRoute + "?apitoken=" + apiToken
	d.sendToBackend(r.Context(), w, r.Method, route, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v WalletBalance %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyLastAnchorV1(w http.ResponseWriter, r *http.Request) {
	d.sendToBackend(r.Context(), w, r.Method, v1.LastAnchorRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v LastAnchor %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyStatusV2(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var s v2.Status
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v2.StatusRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))
	log.Infof("%v Status %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyTimestampV2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	dig := r.Form.Get("digest")
	route := v2.TimestampRoute + "?digest=" + dig
	r.Body.Close()

	d.sendToBackend(r.Context(), w, http.MethodGet, route, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v Timestamp %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyVerifyV2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	dig := r.Form.Get("digest")
	route := v2.VerifyRoute + "?digest=" + dig
	r.Body.Close()

	d.sendToBackend(r.Context(), w, r.Method, route, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v Verify %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyTimestampBatchV2(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var t v2.TimestampBatch
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v2.TimestampBatchRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	for _, v := range t.Digests {
		log.Infof("Timestamp %v: %v", r.RemoteAddr, v)
	}

	log.Infof("%v TimestampBatch %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyVerifyBatchV2(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var v v2.VerifyBatch
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(r.Context(), w, r.Method, v2.VerifyBatchRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	log.Infof("%v VerifyBatch %v: Timestamps %v Digests %v",
		r.URL.Path, r.RemoteAddr, len(v.Timestamps), len(v.Digests))
}

func (d *DcrtimeStore) proxyWalletBalanceV2(w http.ResponseWriter, r *http.Request) {
	apiToken := r.URL.Query().Get("apitoken")
	route := v2.WalletBalanceRoute + "?apitoken=" + apiToken
	d.sendToBackend(r.Context(), w, r.Method, route, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v WalletBalance %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyLastAnchorV2(w http.ResponseWriter, r *http.Request) {
	d.sendToBackend(r.Context(), w, r.Method, v2.LastAnchorRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader([]byte{}))

	log.Infof("%v LastAnchor %v", r.URL.Path, r.RemoteAddr)
}

func (d *DcrtimeStore) proxyLastDigestsV2Route(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var ld v2.LastDigests
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ld); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	d.sendToBackend(r.Context(), w, r.Method, v2.VerifyBatchRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	log.Infof("%v Last Digests %v: Number",
		r.URL.Path, r.RemoteAddr, ld.N)
}

// version returns the supported API versions running on the server.
// Handles /version
func (d *DcrtimeStore) version(w http.ResponseWriter, r *http.Request) {
	var versions []uint
	var prefixes []string
	vs, _ := parseAndValidateAPIVersions(d.cfg.APIVersions)
	for _, v := range vs {
		switch v {
		case v1.APIVersion:
			versions = append(versions, v1.APIVersion)
			prefixes = append(prefixes, v1.RoutePrefix)
		case v2.APIVersion:
			versions = append(versions, v2.APIVersion)
			prefixes = append(prefixes, v2.RoutePrefix)
		}

	}
	versionReply := v2.VersionReply{
		Versions:      versions,
		RoutePrefixes: prefixes,
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	log.Infof("%v Version %v", r.URL.Path, via)

	util.RespondWithJSON(w, http.StatusOK, versionReply)
}

// API v1 Handlers

// statusV1 returns server status information.
// Handles /v1/status.
func (d *DcrtimeStore) statusV1(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var s v1.Status
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	log.Infof("%v Status %v", r.URL.Path, via)

	// Tell client the good news.
	util.RespondWithJSON(w, http.StatusOK, v1.StatusReply(s))
}

// timestampV1 takes multiple digests from a client and sends it to the backend.
// Handles /v1/timestamp.
func (d *DcrtimeStore) timestampV1(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var t v1.Timestamp
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Validate all digests.  If one is invalid return failure.
	digests, err := convertDigests(t.Digests)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Digests array")
		return
	}

	// Push to backend
	ts, me, err := d.backend.Put(digests)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)

		// Tell client there is a transient error.
		if err == backend.ErrTryAgainLater {
			util.RespondWithError(w, http.StatusServiceUnavailable,
				"Server busy, please try again later.")
			return
		}

		// Log what went wrong
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not store payload, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	var (
		result int
		verb   string
	)
	results := make([]int, 0, len(me))
	tsS := time.Unix(ts, 0).UTC().Format(fStr)
	for _, v := range me {
		if v.ErrorCode == backend.ErrorOK {
			verb = "accepted"
			result = v1.ResultOK
		} else {
			verb = "rejected"
			result = v1.ResultExistsError
		}
		results = append(results, result)
		log.Infof("%v Timestamp %v: %v %v %x",
			r.URL.Path, via, verb, tsS, v.Digest)
	}

	// We don't set ChainTimestamp until it is included on the chain.
	util.RespondWithJSON(w, http.StatusOK, v1.TimestampReply{
		ID:              t.ID,
		Digests:         t.Digests,
		ServerTimestamp: ts,
		Results:         results,
	})
}

// verifyV1 takes multiple digests from a client and checks its status on the
// backend.
// Handles /v1/verify.
func (d *DcrtimeStore) verifyV1(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var v v1.Verify
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Validate all digests.  If one is invalid return failure.
	digests, err := convertDigests(v.Digests)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Digests array")
		return
	}

	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", r.RemoteAddr, xff)
	}
	log.Infof("%v Verify %v: Timestamps %v Digests %v",
		r.URL.Path, via, len(v.Timestamps), len(digests))

	// Collect all timestamps.
	tsr, err := d.backend.GetTimestamps(v.Timestamps)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve timestamps, "+
				"contact administrator and provide the"+
				" following error code: %v", errorCode))
		return
	}

	// Translate timestamp results.
	tsReply := make([]v1.VerifyTimestamp, 0, len(tsr))
	for _, ts := range tsr {
		vt := v1.VerifyTimestamp{
			ServerTimestamp: ts.Timestamp,
			CollectionInformation: v1.CollectionInformation{
				ChainTimestamp: ts.AnchoredTimestamp,
				Transaction:    ts.Tx.String(),
				MerkleRoot:     hex.EncodeToString(ts.MerkleRoot[:]),
			},
			Result: -1,
		}

		switch ts.ErrorCode {
		case backend.ErrorOK:
			vt.Result = v1.ResultOK
		case backend.ErrorNotFound:
			vt.Result = v1.ResultDoesntExistError
		case backend.ErrorNotAllowed:
			vt.Result = v1.ResultDisabled
		}
		if vt.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v timestamp ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve timestamps, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}

		// Convert all digests.
		vt.CollectionInformation.Digests = make([]string, 0,
			len(ts.Digests))
		for _, digest := range ts.Digests {
			vt.CollectionInformation.Digests =
				append(vt.CollectionInformation.Digests,
					hex.EncodeToString(digest[:]))
		}

		tsReply = append(tsReply, vt)
	}

	// Digests.
	drs, err := d.backend.Get(digests)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve digests, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Translate digest results.
	dReply := make([]v1.VerifyDigest, 0, len(drs))
	for _, dr := range drs {
		vd := v1.VerifyDigest{
			Digest:          hex.EncodeToString(dr.Digest[:]),
			ServerTimestamp: dr.Timestamp,
			ChainInformation: v1.ChainInformation{
				ChainTimestamp: dr.AnchoredTimestamp,
				Transaction:    dr.Tx.String(),
				MerkleRoot:     hex.EncodeToString(dr.MerkleRoot[:]),
				MerklePath:     dr.MerklePath,
			},
			Result: -1,
		}
		switch dr.ErrorCode {
		case backend.ErrorOK:
			vd.Result = v1.ResultOK
		case backend.ErrorNotFound:
			vd.Result = v1.ResultDoesntExistError
		}

		if vd.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v digest ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve digests, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}

		dReply = append(dReply, vd)
	}

	util.RespondWithJSON(w, http.StatusOK, v1.VerifyReply{
		ID:         v.ID,
		Timestamps: tsReply,
		Digests:    dReply,
	})
}

func (d *DcrtimeStore) lastAnchorV1(w http.ResponseWriter, r *http.Request) {
	log.Infof("%v LastAnchor %v", r.URL.Path, r.RemoteAddr)

	lastAnchorResult, err := d.backend.LastAnchor()
	if err != nil {
		errorCode := time.Now().Unix()

		log.Errorf("%v lastAnchor error code %v: %v",
			r.RemoteAddr, errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve lastest anchor info, "+
				"contact administrator and provide "+
				"the following error code: %v", errorCode))
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.LastAnchorReply{
		ChainTimestamp: lastAnchorResult.ChainTimestamp,
		Transaction:    lastAnchorResult.Tx.String(),
		BlockHash:      lastAnchorResult.BlockHash,
		BlockHeight:    lastAnchorResult.BlockHeight,
	})
}

func (d *DcrtimeStore) walletBalanceV1(w http.ResponseWriter, r *http.Request) {
	if !d.isAuthorized(r) {
		util.RespondWithError(w, http.StatusUnauthorized, "not authorized")
		return
	}

	balanceResult, err := d.backend.GetBalance()
	if err != nil {
		errorCode := time.Now().Unix()

		log.Errorf("%v walletBalance error code %v: %v",
			r.RemoteAddr, errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve wallet balance, "+
				"contact administrator and provide "+
				"the following error code: %v", errorCode))
		return
	}

	log.Infof("%v WalletBalance %v", r.URL.Path, r.RemoteAddr)

	util.RespondWithJSON(w, http.StatusOK, v1.WalletBalanceReply{
		Total:       balanceResult.Total,
		Spendable:   balanceResult.Spendable,
		Unconfirmed: balanceResult.Unconfirmed,
	})
}

// API v2 Handlers

// statusV2 returns server status information.
// Handles /v2/status
func (d *DcrtimeStore) statusV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var s v2.Status
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	log.Infof("%v Status %v", r.URL.Path, via)

	// Tell client the good news.
	util.RespondWithJSON(w, http.StatusOK, v2.StatusReply(s))
}

// timestampBatchV2 takes multiple digests from a client and sends it to the backend.
// Handles /v2/timestamp/batch
func (d *DcrtimeStore) timestampBatchV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var t v2.TimestampBatch
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Validate all digests.  If one is invalid return failure.
	digests, err := convertDigests(t.Digests)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Digests array")
		return
	}

	// Push to backend
	ts, me, err := d.backend.Put(digests)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)

		// Tell client there is a transient error.
		if err == backend.ErrTryAgainLater {
			util.RespondWithError(w, http.StatusServiceUnavailable,
				"Server busy, please try again later.")
			return
		}

		// Log what went wrong
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not store payload, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	var (
		result v2.ResultT
		verb   string
	)
	results := make([]v2.ResultT, 0, len(me))
	tsS := time.Unix(ts, 0).UTC().Format(fStr)
	for _, v := range me {
		if v.ErrorCode == backend.ErrorOK {
			verb = "accepted"
			result = v2.ResultOK
		} else {
			verb = "rejected"
			result = v2.ResultExistsError
		}
		results = append(results, result)
		log.Infof("%v TimestampBatch %v: %v %v %x",
			r.URL.Path, via, verb, tsS, v.Digest)
	}

	// We don't set ChainTimestamp until it is included on the chain.
	util.RespondWithJSON(w, http.StatusOK, v2.TimestampBatchReply{
		ID:              t.ID,
		Digests:         t.Digests,
		ServerTimestamp: ts,
		Results:         results,
	})
}

// verifyBatchV2 takes multiple digests from a client and checks its status on the
// backend.
// Handles /v2/verify/batch
func (d *DcrtimeStore) verifyBatchV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var v v2.VerifyBatch
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	// Validate all digests.  If one is invalid return failure.
	digests, err := convertDigests(v.Digests)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Digests array")
		return
	}

	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", r.RemoteAddr, xff)
	}
	log.Infof("%v VerifyBatch %v: Timestamps %v Digests %v",
		r.URL.Path, via, len(v.Timestamps), len(digests))

	// Collect all timestamps.
	tsr, err := d.backend.GetTimestamps(v.Timestamps)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve timestamps, "+
				"contact administrator and provide the"+
				" following error code: %v", errorCode))
		return
	}

	// Translate timestamp results.
	tsReply := make([]v2.VerifyTimestamp, 0, len(tsr))
	for _, ts := range tsr {
		vt := v2.VerifyTimestamp{
			ServerTimestamp: ts.Timestamp,
			CollectionInformation: v2.CollectionInformation{
				ChainTimestamp:   ts.AnchoredTimestamp,
				Confirmations:    ts.Confirmations,
				MinConfirmations: ts.MinConfirmations,
				Transaction:      ts.Tx.String(),
				MerkleRoot:       hex.EncodeToString(ts.MerkleRoot[:]),
			},
			Result: -1,
		}

		switch ts.ErrorCode {
		case backend.ErrorOK:
			vt.Result = v2.ResultOK
		case backend.ErrorNotFound:
			vt.Result = v2.ResultDoesntExistError
		case backend.ErrorNotAllowed:
			vt.Result = v2.ResultDisabled
		}
		if vt.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v timestamp ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve timestamps, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}

		// Convert all digests.
		vt.CollectionInformation.Digests = make([]string, 0,
			len(ts.Digests))
		for _, digest := range ts.Digests {
			vt.CollectionInformation.Digests =
				append(vt.CollectionInformation.Digests,
					hex.EncodeToString(digest[:]))
		}

		tsReply = append(tsReply, vt)
	}

	// Digests.
	drs, err := d.backend.Get(digests)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve digests, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Translate digest results.
	dReply := make([]v2.VerifyDigest, 0, len(drs))
	for _, dr := range drs {
		vd := v2.VerifyDigest{
			Digest:          hex.EncodeToString(dr.Digest[:]),
			ServerTimestamp: dr.Timestamp,
			ChainInformation: v2.ChainInformation{
				Confirmations:    dr.Confirmations,
				MinConfirmations: dr.MinConfirmations,
				ChainTimestamp:   dr.AnchoredTimestamp,
				Transaction:      dr.Tx.String(),
				MerkleRoot:       hex.EncodeToString(dr.MerkleRoot[:]),
				MerklePath:       dr.MerklePath,
			},
			Result: -1,
		}
		switch dr.ErrorCode {
		case backend.ErrorOK:
			vd.Result = v2.ResultOK
		case backend.ErrorNotFound:
			vd.Result = v2.ResultDoesntExistError
		}

		if vd.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v digest ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve digests, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}
		dReply = append(dReply, vd)
	}

	util.RespondWithJSON(w, http.StatusOK, v2.VerifyBatchReply{
		ID:         v.ID,
		Timestamps: tsReply,
		Digests:    dReply,
	})
}

// timestampV2 takes a single digest from a client and sends it to the backend.
// Receives pure form data in non-json format.
// Handles /v2/timestamp
func (d *DcrtimeStore) timestampV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	r.ParseForm()
	id := r.Form.Get("id")
	dig := r.Form.Get("digest")
	t := v2.Timestamp{
		ID:     id,
		Digest: dig,
	}

	// Validate digest. If it is invalid return failure.
	digest, err := convertDigests([]string{t.Digest})
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Digest")
		return
	}

	// Push to backend
	ts, me, err := d.backend.Put(digest)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)

		// Tell client there is a transient error.
		if err == backend.ErrTryAgainLater {
			util.RespondWithError(w, http.StatusServiceUnavailable,
				"Server busy, please try again later.")
			return
		}

		// Log what went wrong
		log.Errorf("%v timestamp error code %v: %v", r.RemoteAddr,
			errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not store payload, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Log for audit trail and reuse loop to translate MultiError to JSON
	// Results.
	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	var (
		result v2.ResultT
		verb   string
	)
	pr := me[len(me)-1] // Digest from PutResult
	tsS := time.Unix(ts, 0).UTC().Format(fStr)
	if pr.ErrorCode == backend.ErrorOK {
		verb = "accepted"
		result = v2.ResultOK
	} else {
		verb = "rejected"
		result = v2.ResultExistsError
	}
	log.Infof("%v Timestamp %v: %v %v %x",
		r.URL.Path, via, verb, tsS, pr.Digest)

	util.RespondWithJSON(w, http.StatusOK, v2.TimestampReply{
		ID:              t.ID,
		Digest:          t.Digest,
		ServerTimestamp: ts,
		Result:          result,
	})
}

// verifyV2 takes a single digest from a client and checks its status on the
// backend. Receives pure form data in non-json format.
// Handles /v2/verify
func (d *DcrtimeStore) verifyV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	r.ParseForm()
	id := r.Form.Get("id")
	dig := r.Form.Get("digest")
	timestamp := r.Form.Get("timestamp")
	tsint, _ := strconv.ParseInt(timestamp, 10, 64)
	v := v2.Verify{
		ID:        id,
		Digest:    dig,
		Timestamp: tsint,
	}

	// Validate request parameters.
	if v.Digest == "" && v.Timestamp == 0 {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid Request parameters")
		return
	}

	// Validate digest.
	var digs []string
	// If digest parameter was set in the request, convert it.
	// Otherwise, pass empty array to convertDigest so it doesn't
	// error out.
	if v.Digest != "" {
		digs = append(digs, v.Digest)
	}
	digest, err := convertDigests(digs)
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest, "Invalid Digest")
		return
	}

	via := r.RemoteAddr
	xff := r.Header.Get(forward)
	if xff != "" {
		via = fmt.Sprintf("%v via %v", r.RemoteAddr, xff)
	}
	log.Infof("%v Verify %v: Timestamp %v Digest %v",
		r.URL.Path, via, v.Timestamp, v.Digest)

	// Collect timestamp, in case it was set in the request.
	var ts []int64
	if v.Timestamp != 0 {
		ts = append(ts, v.Timestamp)
	}
	tsr, err := d.backend.GetTimestamps(ts)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve timestamp, "+
				"contact administrator and provide the"+
				" following error code: %v", errorCode))
		return
	}

	// Translate timestamp result.
	var tsReply v2.VerifyTimestamp
	if len(tsr) != 0 {
		ts := tsr[len(tsr)-1]
		vt := v2.VerifyTimestamp{
			ServerTimestamp: ts.Timestamp,
			CollectionInformation: v2.CollectionInformation{
				ChainTimestamp:   ts.AnchoredTimestamp,
				Confirmations:    ts.Confirmations,
				MinConfirmations: ts.MinConfirmations,
				Transaction:      ts.Tx.String(),
				MerkleRoot:       hex.EncodeToString(ts.MerkleRoot[:]),
			},
			Result: -1,
		}

		switch ts.ErrorCode {
		case backend.ErrorOK:
			vt.Result = v2.ResultOK
		case backend.ErrorNotFound:
			vt.Result = v2.ResultDoesntExistError
		case backend.ErrorNotAllowed:
			vt.Result = v2.ResultDisabled
		}
		if vt.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v timestamp ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve timestamps, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}

		// Convert all digests.
		vt.CollectionInformation.Digests = make([]string, 0,
			len(ts.Digests))
		for _, digest := range ts.Digests {
			vt.CollectionInformation.Digests =
				append(vt.CollectionInformation.Digests,
					hex.EncodeToString(digest[:]))
		}

		tsReply = vt
	}

	// Digest.
	drs, err := d.backend.Get(digest)
	if err != nil {
		// Generic internal error.
		errorCode := time.Now().Unix()
		log.Errorf("%v verify error code %v: %v", r.RemoteAddr,
			errorCode, err)

		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieve digests, contact "+
				"administrator and provide the following "+
				"error code: %v", errorCode))
		return
	}

	// Translate digest results.
	var dReply v2.VerifyDigest
	if len(drs) != 0 {
		dr := drs[len(drs)-1]
		vd := v2.VerifyDigest{
			Digest:          hex.EncodeToString(dr.Digest[:]),
			ServerTimestamp: dr.Timestamp,
			ChainInformation: v2.ChainInformation{
				Confirmations:    dr.Confirmations,
				MinConfirmations: dr.MinConfirmations,
				ChainTimestamp:   dr.AnchoredTimestamp,
				Transaction:      dr.Tx.String(),
				MerkleRoot:       hex.EncodeToString(dr.MerkleRoot[:]),
				MerklePath:       dr.MerklePath,
			},
			Result: -1,
		}
		switch dr.ErrorCode {
		case backend.ErrorOK:
			vd.Result = v2.ResultOK
		case backend.ErrorNotFound:
			vd.Result = v2.ResultDoesntExistError
		}

		if vd.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v digest ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve digests, "+
					"contact administrator and provide "+
					"the following error code: %v",
					errorCode))
			return
		}
		dReply = vd
	}

	util.RespondWithJSON(w, http.StatusOK, v2.VerifyReply{
		ID:        v.ID,
		Timestamp: tsReply,
		Digest:    dReply,
	})
}

func (d *DcrtimeStore) lastAnchorV2(w http.ResponseWriter, r *http.Request) {
	log.Infof("%v LastAnchor %v", r.URL.Path, r.RemoteAddr)

	lastAnchorResult, err := d.backend.LastAnchor()
	if err != nil {
		errorCode := time.Now().Unix()

		log.Errorf("%v lastAnchor error code %v: %v",
			r.RemoteAddr, errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve lastest anchor info, "+
				"contact administrator and provide "+
				"the following error code: %v", errorCode))
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v2.LastAnchorReply{
		ChainTimestamp: lastAnchorResult.ChainTimestamp,
		Transaction:    lastAnchorResult.Tx.String(),
		BlockHash:      lastAnchorResult.BlockHash,
		BlockHeight:    lastAnchorResult.BlockHeight,
	})
}

func (d *DcrtimeStore) lastDigestsV2(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var ld v2.LastDigests
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ld); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	log.Infof("%v LastDigests %v", r.URL.Path, r.RemoteAddr)

	ldr, err := d.backend.LastDigests(ld.N)
	if err != nil {
		errorCode := time.Now().Unix()

		log.Errorf("%v LastDigests error code %v: %v",
			r.RemoteAddr, errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve latest %d digests info, "+
				"contact administrator and provide "+
				"the following error code: %v", ld.N, errorCode))
		return
	}

	vdReply := make([]v2.VerifyDigest, 0, len(ldr))
	for _, vr := range ldr {
		vd := v2.VerifyDigest{
			Digest:          hex.EncodeToString(vr.Digest[:]),
			ServerTimestamp: vr.Timestamp,
			ChainInformation: v2.ChainInformation{
				ChainTimestamp:   vr.AnchoredTimestamp,
				Confirmations:    vr.Confirmations,
				MinConfirmations: vr.MinConfirmations,
				Transaction:      vr.Tx.String(),
				MerkleRoot:       hex.EncodeToString(vr.MerkleRoot[:]),
				MerklePath:       vr.MerklePath,
			},
			Result: -1,
		}

		switch vr.ErrorCode {
		case backend.ErrorOK:
			vd.Result = v2.ResultOK
		case backend.ErrorNotFound:
			vd.Result = v2.ResultDoesntExistError
		}

		if vd.Result == -1 {
			// Generic internal error.
			errorCode := time.Now().Unix()
			log.Errorf("%v digest ErrorCode translation error "+
				"code %v: %v", r.RemoteAddr, errorCode, err)

			util.RespondWithError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve last %d digests, "+
					"contact administrator and provide "+
					"the following error code: %v",
					ld.N, errorCode))
			return
		}
		vdReply = append(vdReply, vd)
	}

	util.RespondWithJSON(w, http.StatusOK, v2.LastDigestsReply{
		Digests: vdReply,
	})
}

// walletBalanceV2 takes an apitoken get param and returns balance information
// of the wallet.
func (d *DcrtimeStore) walletBalanceV2(w http.ResponseWriter, r *http.Request) {
	if !d.isAuthorized(r) {
		util.RespondWithError(w, http.StatusUnauthorized, "not authorized")
		return
	}

	log.Infof("%v WalletBalance %v", r.URL.Path, r.RemoteAddr)

	balanceResult, err := d.backend.GetBalance()
	if err != nil {
		errorCode := time.Now().Unix()

		log.Errorf("%v walletBalance error code %v: %v",
			r.RemoteAddr, errorCode, err)
		util.RespondWithError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to retrieve wallet balance, "+
				"contact administrator and provide "+
				"the following error code: %v", errorCode))
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v2.WalletBalanceReply{
		Total:       balanceResult.Total,
		Spendable:   balanceResult.Spendable,
		Unconfirmed: balanceResult.Unconfirmed,
	})
}

// isAuthorized returns true if the first api token query parameter
// matches any APIToken configuration value. Otherwise, it returns false.
func (d *DcrtimeStore) isAuthorized(r *http.Request) bool {
	apiToken := r.URL.Query().Get("apitoken")
	if _, exist := d.apiTokens[apiToken]; exist {
		return true
	}

	log.Errorf("isAuthorized %v: authentication failed", r.RemoteAddr)
	return false
}

// convertDigests receives an array of string digests and converts it to
// sha256, format currently being used throughout the code.
func convertDigests(d []string) ([][sha256.Size]byte, error) {
	result := make([][sha256.Size]byte, 0, len(d))

	for _, digest := range d {
		hash, err := hex.DecodeString(digest)
		if err != nil {
			return nil, err
		}
		if len(hash) != sha256.Size {
			return nil, fmt.Errorf("invalid length")
		}
		var h [sha256.Size]byte
		copy(h[:], hash)
		result = append(result, h)
	}

	return result, nil
}

// getError returns the error that is embedded in a JSON reply.
func getError(r io.Reader) (string, error) {
	var e interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&e); err != nil {
		return "", err
	}
	m, ok := e.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Could not decode response")
	}
	rError, ok := m["error"]
	if !ok {
		return "", fmt.Errorf("No error response")
	}
	return fmt.Sprintf("%v", rError), nil
}

// apiTokenMap converts the APITokens config values to a map
func apiTokenMap(cfg *config) map[string]struct{} {
	lookup := make(map[string]struct{})
	for _, token := range cfg.APITokens {
		lookup[token] = struct{}{}
	}
	return lookup
}

// closeBody wraps the provided function as a closure and returns a new
// function that ensures the request body is closed. This is done to avoid
// resource leaks.
func closeBody(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		r.Body.Close()
	}
}

// addRoute adds the route on the provided DcrtimeStore's router and ensures
// that the request body is closed after handling the request, to avoid leaks.
func (d *DcrtimeStore) addRoute(method string, route string, handler http.HandlerFunc) {
	closedHandler := closeBody(handler)
	d.router.HandleFunc(route, closedHandler).Methods(method)
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	var proxy bool
	mode := "Store"
	if loadedCfg.StoreHost != "" {
		proxy = true
		mode = "Proxy"
	}
	log.Infof("Version : %v", version())
	log.Infof("Mode    : %v", mode)
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair("dcrtimed", loadedCfg.HTTPSCert,
			loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Setup application context
	d := &DcrtimeStore{
		cfg:       loadedCfg,
		ctx:       context.Background(),
		apiTokens: apiTokenMap(loadedCfg),
	}

	var certPool *x509.CertPool
	if proxy {
		if !fileExists(loadedCfg.StoreCert) {
			return fmt.Errorf("unable to find store cert %v",
				loadedCfg.StoreCert)
		}
		storeCert, err := ioutil.ReadFile(loadedCfg.StoreCert)
		if err != nil {
			return fmt.Errorf("unable to read store cert %v: %v",
				loadedCfg.StoreCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(storeCert) {
			return fmt.Errorf("unable to load cert")
		}
	} else {
		// Setup backend.
		filesystem.UseLogger(fsbeLog)
		b, err := filesystem.New(loadedCfg.DataDir,
			loadedCfg.WalletCert,
			loadedCfg.WalletHost,
			loadedCfg.WalletClientCert,
			loadedCfg.WalletClientKey,
			loadedCfg.EnableCollections,
			loadedCfg.Confirmations,
			[]byte(loadedCfg.WalletPassphrase))

		if err != nil {
			return err
		}

		d.backend = b
	}

	// Setup mux
	d.router = mux.NewRouter()

	// API v1 routes
	var statusV1Route func(http.ResponseWriter, *http.Request)
	var timestampV1Route func(http.ResponseWriter, *http.Request)
	var verifyV1Route func(http.ResponseWriter, *http.Request)
	var walletBalanceV1Route http.HandlerFunc
	var lastAnchorV1Route http.HandlerFunc

	// API v2 routes
	var statusV2Route func(http.ResponseWriter, *http.Request)
	var timestampBatchV2Route func(http.ResponseWriter, *http.Request)
	var verifyBatchV2Route func(http.ResponseWriter, *http.Request)
	var timestampV2Route func(http.ResponseWriter, *http.Request)
	var verifyV2Route func(http.ResponseWriter, *http.Request)
	var walletBalanceV2Route http.HandlerFunc
	var lastAnchorV2Route http.HandlerFunc
	var lastDigestsV2Route func(http.ResponseWriter, *http.Request)

	if certPool != nil {
		// PROXY ENABLED
		tlsConfig := &tls.Config{
			RootCAs: certPool,
		}
		tr := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		d.httpClient = &http.Client{Transport: tr}

		statusV1Route = d.proxyStatusV1
		timestampV1Route = d.proxyTimestampV1
		verifyV1Route = d.proxyVerifyV1
		walletBalanceV1Route = d.proxyWalletBalanceV1
		lastAnchorV1Route = d.proxyLastAnchorV1

		statusV2Route = d.proxyStatusV2
		timestampBatchV2Route = d.proxyTimestampBatchV2
		verifyBatchV2Route = d.proxyVerifyBatchV2
		timestampV2Route = d.proxyTimestampV2
		verifyV2Route = d.proxyVerifyV2
		walletBalanceV2Route = d.proxyWalletBalanceV2
		lastAnchorV2Route = d.proxyLastAnchorV2
		lastDigestsV2Route = d.proxyLastDigestsV2Route
	} else {
		statusV1Route = d.statusV1
		timestampV1Route = d.timestampV1
		verifyV1Route = d.verifyV1
		walletBalanceV1Route = d.walletBalanceV1
		lastAnchorV1Route = d.lastAnchorV1

		statusV2Route = d.statusV2
		timestampBatchV2Route = d.timestampBatchV2
		verifyBatchV2Route = d.verifyBatchV2
		timestampV2Route = d.timestampV2
		verifyV2Route = d.verifyV2
		walletBalanceV2Route = d.walletBalanceV2
		lastAnchorV2Route = d.lastAnchorV2
		lastDigestsV2Route = d.lastDigestsV2
	}

	// Top-level route handler
	d.addRoute(http.MethodGet, v2.VersionRoute, d.version)

	versions, _ := parseAndValidateAPIVersions(loadedCfg.APIVersions)

	// Add handlers according to supported API versions in cfg
	for _, v := range versions {
		switch v {
		case v1.APIVersion:
			// API v1 handlers
			d.addRoute(http.MethodPost, v1.StatusRoute, statusV1Route)
			d.addRoute(http.MethodPost, v1.TimestampRoute, timestampV1Route)
			d.addRoute(http.MethodPost, v1.VerifyRoute, verifyV1Route)
			d.addRoute(http.MethodGet, v1.WalletBalanceRoute, walletBalanceV1Route)
			d.addRoute(http.MethodGet, v1.LastAnchorRoute, lastAnchorV1Route)
		case v2.APIVersion:
			// API v2 handlers
			d.addRoute(http.MethodPost, v2.StatusRoute, statusV2Route)
			d.addRoute(http.MethodPost, v2.TimestampBatchRoute, timestampBatchV2Route)
			d.addRoute(http.MethodPost, v2.VerifyBatchRoute, verifyBatchV2Route)
			d.addRoute(http.MethodGet, v2.WalletBalanceRoute, walletBalanceV2Route)
			d.addRoute(http.MethodGet, v2.LastAnchorRoute, lastAnchorV2Route)
			d.addRoute(http.MethodPost, v2.LastDigestsRoute, lastDigestsV2Route)
			d.router.HandleFunc(v2.TimestampRoute, timestampV2Route).Methods(http.MethodPost, http.MethodGet)
			d.router.HandleFunc(v2.VerifyRoute, verifyV2Route).Methods(http.MethodPost, http.MethodGet)
		}
	}

	// Handle non-api /status as well
	if trimmed := strings.TrimSuffix(v1.StatusRoute, "/"); trimmed != v1.StatusRoute {
		d.addRoute("get", trimmed, statusV1Route)
	}

	// Pretty print web page for individual digest/timestamp
	//d.router.HandleFunc(v1.TimestampRoute+"{id:[0-9a-zA-Z]+}",
	//	d.getTimestamp).Methods(http.MethodGet)

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			// CORS options
			origins := handlers.AllowedOrigins([]string{"*"})
			methods := handlers.AllowedMethods([]string{http.MethodGet, http.MethodOptions, http.MethodPost})
			headers := handlers.AllowedHeaders([]string{"Content-Type"})

			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				handlers.CORS(origins, methods, headers)(d.router))
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, interruptSignals...)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:
	if !proxy {
		d.backend.Close()
	}

	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
