// Copyright (c) 2017 The Decred developers
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
	"syscall"
	"time"

	"github.com/decred/dcrtime/api/v1"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
	"github.com/decred/dcrtime/util"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/gorilla/mux"
)

const (
	fStr = "20060102.150405"

	forward = "X-Forwarded-For"
)

// DcrtimeStore application context.
type DcrtimeStore struct {
	backend    backend.Backend
	cfg        *config
	router     *mux.Router
	ctx        context.Context
	wallet     pb.WalletServiceClient
	httpClient *http.Client
}

func (d *DcrtimeStore) sendToBackend(w http.ResponseWriter, route, contentType, remoteAddr string, body *bytes.Reader) {
	storeHost := fmt.Sprintf("https://%s%s", d.cfg.StoreHost, route)

	req, err := http.NewRequest("POST", storeHost, body)
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
		e, err := getError(resp.Body)
		if err != nil {
			log.Errorf("Bad status posting to %v: %v", storeHost,
				resp.Status)
		} else {
			log.Errorf("Bad status posting to %v: %v\n%v",
				storeHost, resp.Status, e)
		}
		util.RespondWithError(w, http.StatusInternalServerError,
			string(bodyBuf.Bytes()))
		return
	}

	err = util.RespondWithCopy(w, resp.StatusCode,
		resp.Header.Get("Content-Type"), bodyBuf.Bytes())
	if err != nil {
		log.Errorf("Error responding to client: %v", err)
	}
}

func (d *DcrtimeStore) proxyTimestamp(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var t v1.Timestamp
	decoder := json.NewDecoder(bytes.NewReader(b))
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(w, v1.TimestampRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))

	for _, v := range t.Digests {
		log.Infof("Timestamp %v: %v", r.RemoteAddr, v)
	}
}

func (d *DcrtimeStore) proxyVerify(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Unable to read request")
		return
	}

	var v v1.Verify
	decoder := json.NewDecoder(bytes.NewReader(b))
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}

	d.sendToBackend(w, v1.VerifyRoute, r.Header.Get("Content-Type"),
		r.RemoteAddr, bytes.NewReader(b))
	log.Infof("Verify %v: Timestamps %v Digests %v",
		r.RemoteAddr, len(v.Timestamps), len(v.Digests))
}

func convertBinary(digests [][sha256.Size]byte) []string {
	result := make([]string, 0, len(digests))
	for _, h := range digests {
		result = append(result, hex.EncodeToString(h[:]))
	}
	return result
}

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

// timestamp takes a frontend timestamp and sends it off to the backend.
func (d *DcrtimeStore) timestamp(w http.ResponseWriter, r *http.Request) {
	var t v1.Timestamp
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

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
		log.Infof("Timestamp %v: %v %v %x", via, verb, tsS, v.Digest)
	}

	// We don't set ChainTimestamp until it is included on the chain.
	util.RespondWithJSON(w, http.StatusOK, v1.TimestampReply{
		ID:              t.ID,
		Digests:         t.Digests,
		ServerTimestamp: ts,
		Results:         results,
	})
}

func (d *DcrtimeStore) verify(w http.ResponseWriter, r *http.Request) {
	var v v1.Verify
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		util.RespondWithError(w, http.StatusBadRequest,
			"Invalid request payload")
		return
	}
	defer r.Body.Close()

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
	log.Infof("Verify %v: Timestamps %v Digests %v",
		via, len(v.Timestamps), len(digests))

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

	// Tell client the good news.
	util.RespondWithJSON(w, http.StatusOK, v1.VerifyReply{
		ID:         v.ID,
		Timestamps: tsReply,
		Digests:    dReply,
	})
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
		cfg: loadedCfg,
		ctx: context.Background(),
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
			loadedCfg.WalletCert, loadedCfg.WalletHost,
			loadedCfg.EnableCollections,
			[]byte(loadedCfg.WalletPassphrase))
		if err != nil {
			return err
		}
		d.backend = b
	}

	// Setup mux
	d.router = mux.NewRouter()

	if certPool != nil {
		// PROXY ENABLED
		tlsConfig := &tls.Config{
			RootCAs: certPool,
		}
		tr := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		d.httpClient = &http.Client{Transport: tr}
		d.router.HandleFunc(v1.TimestampRoute,
			d.proxyTimestamp).Methods("POST")
		d.router.HandleFunc(v1.VerifyRoute,
			d.proxyVerify).Methods("POST")
	} else {
		d.router.HandleFunc(v1.TimestampRoute,
			d.timestamp).Methods("POST")
		d.router.HandleFunc(v1.VerifyRoute,
			d.verify).Methods("POST")
	}

	// Pretty print web page for individual digest/timestamp
	//d.router.HandleFunc(v1.TimestampRoute+"{id:[0-9a-zA-Z]+}",
	//	d.getTimestamp).Methods("GET")

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				d.router)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
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
