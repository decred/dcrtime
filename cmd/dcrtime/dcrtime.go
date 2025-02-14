// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	v1 "github.com/decred/dcrtime/api/v1"
	v2 "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/dcrtime/util"
)

const (
	dcrtimeClientID = "dcrtime cli"
)

var (
	testnet   = flag.Bool("testnet", false, "Use testnet port")
	debug     = flag.Bool("debug", false, "Print JSON that is sent to server")
	printJSON = flag.Bool("json", false, "Print JSON response from server")
	fileOnly  = flag.Bool("file", false, "Treat digests and timestamps "+
		"as file names")
	host     = flag.String("h", "", "Timestamping host")
	port     = flag.String("p", "", "Timestamping host port")
	trial    = flag.Bool("t", false, "Trial run, don't contact server")
	verbose  = flag.Bool("v", false, "Verbose")
	digest   = flag.String("digest", "", "Submit a raw 256 bit digest to anchor")
	apiToken = flag.String("apitoken", "", "Token for accessing privileged API"+
		" resources")
	balance = flag.Bool("balance", false, "Display the connected server's"+
		" wallet balance. An API Token is required")
	lastAnchor = flag.Bool("lastanchor", false, "Display last anchored"+
		" timestamp details")
	lastDigests = flag.Bool("lastdigests", false, "Display last digests"+
		"details. Sorted from newest to oldest. digestsnumber is required")
	apiVersion = flag.Int("api", v2.APIVersion,
		"Inform the API version to be used by the cli (1 or 2)")
	skipVerify = flag.Bool("skipverify", false, "Skip TLS certificates"+
		"verification (not recommended)")
	digestsNumber = flag.Int("digestsnumber", 0, "The number of digests to get. Sorted from newest to oldest")
)

// normalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func normalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// isDir determines if the provided filename points to a directory.
func isDir(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return fi.Mode().IsDir()
}

// isFile determines if the provided filename points to a valid file.
func isFile(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

// isDigest determines if a string is a valid SHA256 digest.
func isDigest(digest string) bool {
	return v2.RegexpSHA256.MatchString(digest)
}

// isTimestamp determines if a string is a valid UNIX timestamp.
func isTimestamp(timestamp string) bool {
	return v2.RegexpTimestamp.MatchString(timestamp)
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
		return "", fmt.Errorf("could not decode response")
	}
	rError, ok := m["error"]
	if !ok {
		return "", fmt.Errorf("no error response")
	}
	return fmt.Sprintf("%v", rError), nil
}

func convertTimestamp(t string) (int64, bool) {
	if !isTimestamp(t) {
		return 0, false
	}

	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, false
	}

	return ts, true
}

func convertDigest(d string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if !isDigest(d) {
		return digest, false
	}

	dd, err := hex.DecodeString(d)
	if err != nil {
		return digest, false
	}
	copy(digest[:], dd)

	return digest, true
}

func newClient(skipVerify bool) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr}
}

func downloadV1(questions []string) error {
	ver := v1.Verify{
		ID: dcrtimeClientID,
	}

	for _, question := range questions {
		if ts, ok := convertTimestamp(question); ok {
			ver.Timestamps = append(ver.Timestamps, ts)
			continue
		}

		if isDigest(question) {
			ver.Digests = append(ver.Digests, question)
			continue
		}

		return fmt.Errorf("not a digest or timestamp: %v", question)
	}

	// Convert Verify to JSON
	b, err := json.Marshal(ver)
	if err != nil {
		return err
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	route := *host + v1.VerifyRoute

	if *debug {
		fmt.Println(string(b))
		fmt.Println(route)
	}

	c := newClient(*skipVerify)
	r, err := c.Post(route, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	// Decode response.
	var vr v1.VerifyReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vr); err != nil {
		return fmt.Errorf("could node decode VerifyReply: %v", err)
	}

	for _, v := range vr.Timestamps {
		result, ok := v1.Result[v.Result]
		if !ok {
			fmt.Printf("%v invalid error code %v\n", v.ServerTimestamp,
				v.Result)
			continue
		}

		// Verify results if the collection is anchored.
		if v.CollectionInformation.ChainTimestamp != 0 {
			// Calculate merkle root of all digests.
			digests := make([]*[sha256.Size]byte, 0,
				len(v.CollectionInformation.Digests))
			for _, digest := range v.CollectionInformation.Digests {
				d, ok := convertDigest(digest)
				if !ok {
					return fmt.Errorf("Invalid digest "+
						"server response for "+
						"timestamp: %v",
						v.ServerTimestamp)
				}
				digests = append(digests, &d)
			}
			root := merkle.Root(digests)
			if hex.EncodeToString(root[:]) !=
				v.CollectionInformation.MerkleRoot {
				fmt.Printf("invalid merkle root: %v\n", err)
			}
		}

		// Print the good news.
		if v.CollectionInformation.ChainTimestamp == 0 &&
			v.Result == v1.ResultOK {
			result = "Not anchored"
		}
		fmt.Printf("%v %v\n", v.ServerTimestamp, result)

		if !*verbose {
			continue
		}

		prefix := "Digests"
		for _, digest := range v.CollectionInformation.Digests {
			fmt.Printf("  %-15v: %v\n", prefix, digest)
			prefix = ""
		}

		// Only print additional info if we are anchored
		if v.CollectionInformation.ChainTimestamp == 0 {
			continue
		}
		fmt.Printf("  %-15v: %v\n", "Chain Timestamp",
			v.CollectionInformation.ChainTimestamp)
		fmt.Printf("  %-15v: %v\n", "Merkle Root",
			v.CollectionInformation.MerkleRoot)
		fmt.Printf("  %-15v: %v\n", "TxID",
			v.CollectionInformation.Transaction)
	}

	for _, v := range vr.Digests {
		result, ok := v1.Result[v.Result]
		if !ok {
			fmt.Printf("%v invalid error code %v\n", v.Digest,
				v.Result)
			continue
		}

		// Verify merkle path.
		root, err := merkle.VerifyAuthPath(&v.ChainInformation.MerklePath)
		if err != nil {
			if err != merkle.ErrEmpty {
				fmt.Printf("%v invalid auth path %v\n",
					v.Digest, err)
				continue
			}
			fmt.Printf("%v Not anchored\n", v.Digest)
			continue
		}

		// Verify merkle root.
		merkleRoot, err := hex.DecodeString(v.ChainInformation.MerkleRoot)
		if err != nil {
			fmt.Printf("invalid merkle root: %v\n", err)
			continue
		}
		// This is silly since we check against returned root.
		if !bytes.Equal(root[:], merkleRoot) {
			fmt.Printf("%v invalid merkle root\n", v.Digest)
			continue
		}

		// Print the good news.
		fmt.Printf("%v %v\n", v.Digest, result)

		if !*verbose {
			continue
		}
		fmt.Printf("  %-15v: %v\n", "Chain Timestamp",
			v.ChainInformation.ChainTimestamp)
		fmt.Printf("  %-15v: %v\n", "Merkle Root",
			v.ChainInformation.MerkleRoot)
		fmt.Printf("  %-15v: %v\n", "TxID",
			v.ChainInformation.Transaction)
	}

	return nil
}

func downloadV2Batch(questions []string) error {
	ver := v2.VerifyBatch{
		ID: dcrtimeClientID,
	}

	// Check if questions are valid.
	for _, question := range questions {
		if ts, ok := convertTimestamp(question); ok {
			ver.Timestamps = append(ver.Timestamps, ts)
			continue
		}

		if isDigest(question) {
			ver.Digests = append(ver.Digests, question)
			continue
		}

		return fmt.Errorf("not a digest or timestamp: %v", question)
	}

	// Convert Verify to JSON
	b, err := json.Marshal(ver)
	if err != nil {
		return err
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	route := *host + v2.VerifyBatchRoute

	if *debug {
		fmt.Println(string(b))
		fmt.Println(route)
	}

	c := newClient(*skipVerify)
	r, err := c.Post(route, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	// Decode response.
	var vbr v2.VerifyBatchReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vbr); err != nil {
		return fmt.Errorf("could node decode VerifyReply: %v", err)
	}

	verifyDigests(vbr.Digests)

	err = verifyTimestamps(vbr.Timestamps)
	if err != nil {
		return err
	}

	return nil
}

func verifyDigests(vd []v2.VerifyDigest) {
	for _, d := range vd {
		result, ok := v2.Result[d.Result]
		if !ok {
			fmt.Printf("%v invalid error code %v\n", d.Digest,
				d.Result)
			continue
		}

		// Verify merkle path.
		root, err := merkle.VerifyAuthPath((*merkle.Branch)(&d.ChainInformation.MerklePath))
		if err != nil {
			if err != merkle.ErrEmpty {
				fmt.Printf("%v invalid auth path %v\n",
					d.Digest, err)
				continue
			}
			fmt.Printf("%v Not anchored\n", d.Digest)
			continue
		}

		// Verify merkle root.
		merkleRoot, err := hex.DecodeString(d.ChainInformation.MerkleRoot)
		if err != nil {
			fmt.Printf("invalid merkle root: %v\n", err)
			continue
		}
		// This is silly since we check against returned root.
		if !bytes.Equal(root[:], merkleRoot) {
			fmt.Printf("%v invalid merkle root\n", d.Digest)
			continue
		}

		// Print the good news.
		fmt.Printf("%v %v\n", d.Digest, result)

		if !*verbose {
			continue
		}
		fmt.Printf("  %-15v: %v\n", "Chain Timestamp",
			d.ChainInformation.ChainTimestamp)
		fmt.Printf("  %-15v: %v\n", "Merkle Root",
			d.ChainInformation.MerkleRoot)
		fmt.Printf("  %-15v: %v\n", "TxID",
			d.ChainInformation.Transaction)
	}
}

func verifyTimestamps(vt []v2.VerifyTimestamp) error {
	for _, t := range vt {
		result, ok := v2.Result[t.Result]
		if !ok {
			fmt.Printf("%v invalid error code %v\n", t.ServerTimestamp,
				t.Result)
			continue
		}

		// Verify results if the collection is anchored.
		if t.CollectionInformation.ChainTimestamp != 0 {
			// Calculate merkle root of all digests.
			digests := make([]*[sha256.Size]byte, 0,
				len(t.CollectionInformation.Digests))
			for _, digest := range t.CollectionInformation.Digests {
				d, ok := convertDigest(digest)
				if !ok {
					return fmt.Errorf("Invalid digest "+
						"server response for "+
						"timestamp: %v",
						t.ServerTimestamp)
				}
				digests = append(digests, &d)
			}
			root := merkle.Root(digests)
			if hex.EncodeToString(root[:]) !=
				t.CollectionInformation.MerkleRoot {
				fmt.Printf("invalid merkle root\n")
			}
		}

		// Print the good news.
		if t.CollectionInformation.ChainTimestamp == 0 &&
			t.Result == v2.ResultOK {
			result = "Not anchored"
		}
		fmt.Printf("%v %v\n", t.ServerTimestamp, result)

		if !*verbose {
			continue
		}

		prefix := "Digests"
		for _, digest := range t.CollectionInformation.Digests {
			fmt.Printf("  %-15v: %v\n", prefix, digest)
			prefix = ""
		}

		// Only print additional info if we are anchored
		if t.CollectionInformation.ChainTimestamp == 0 {
			continue
		}
		fmt.Printf("  %-15v: %v\n", "Chain Timestamp",
			t.CollectionInformation.ChainTimestamp)
		fmt.Printf("  %-15v: %v\n", "Merkle Root",
			t.CollectionInformation.MerkleRoot)
		fmt.Printf("  %-15v: %v\n", "TxID",
			t.CollectionInformation.Transaction)
	}

	return nil
}

func uploadV1(digests []string, exists map[string]string) error {
	// batch uploads
	ts := v1.Timestamp{
		ID:      dcrtimeClientID,
		Digests: digests,
	}
	b, err := json.Marshal(ts)
	if err != nil {
		return err
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	route := *host + v1.TimestampRoute

	if *debug {
		fmt.Println(string(b))
		fmt.Println(route)
	}

	c := newClient(*skipVerify)
	r, err := c.Post(route, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	// Decode response.
	var tsReply v1.TimestampReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tsReply); err != nil {
		return fmt.Errorf("Could node decode TimestampReply: %v", err)
	}

	// Print human readable results.
	for k, v := range tsReply.Results {
		filename := exists[tsReply.Digests[k]]
		if v == v1.ResultOK {
			fmt.Printf("%v OK %v\n", tsReply.Digests[k], filename)
			continue
		}
		fmt.Printf("%v Exists %v\n", tsReply.Digests[k], filename)
	}

	if *verbose {
		// Print server timestamp.
		fmt.Printf("Collection timestamp: %v\n", tsReply.ServerTimestamp)
	}

	return nil
}

func uploadV2Batch(digests []string, exists map[string]string) error {
	// batch uploads
	ts := v2.TimestampBatch{
		ID:      dcrtimeClientID,
		Digests: digests,
	}
	b, err := json.Marshal(ts)
	if err != nil {
		return err
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	route := *host + v2.TimestampBatchRoute

	if *debug {
		fmt.Println(string(b))
		fmt.Println(route)
	}

	c := newClient(*skipVerify)
	r, err := c.Post(route, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	// Decode response.
	var tsReply v2.TimestampBatchReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tsReply); err != nil {
		return fmt.Errorf("Could node decode TimestampReply: %v", err)
	}

	// Print human readable results.
	for k, v := range tsReply.Results {
		filename := exists[tsReply.Digests[k]]
		if v == v2.ResultOK {
			fmt.Printf("%v OK %v\n", tsReply.Digests[k], filename)
			continue
		}
		fmt.Printf("%v Exists %v\n", tsReply.Digests[k], filename)
	}

	if *verbose {
		// Print server timestamp.
		fmt.Printf("Collection timestamp: %v\n", tsReply.ServerTimestamp)
	}

	return nil
}

func uploadV2Single(digest string, exists map[string]string) error {
	ts := v2.Timestamp{
		ID:     dcrtimeClientID,
		Digest: digest,
	}
	formParam := url.Values{}
	formParam.Set("digest", digest)

	// If this is a trial run return.
	if *trial {
		return nil
	}

	route := *host + v2.TimestampRoute

	if *debug {
		fmt.Println(ts)
		fmt.Println(route)
	}

	c := newClient(*skipVerify)
	r, err := c.PostForm(route, formParam)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	// Decode response.
	var tsReply v2.TimestampReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tsReply); err != nil {
		return fmt.Errorf("Could node decode TimestampReply: %v", err)
	}

	// Print human readable results.
	filename := exists[tsReply.Digest]
	if tsReply.Result == v2.ResultOK {
		fmt.Printf("%v OK %v\n", tsReply.Digest, filename)
	} else {
		fmt.Printf("%v Exists %v\n", tsReply.Digest, filename)
	}

	if *verbose {
		// Print server timestamp.
		fmt.Printf("Collection timestamp: %v\n", tsReply.ServerTimestamp)
	}

	return nil
}

func uploadV2(digests []string, exists map[string]string) error {
	var err error
	switch len(digests) {
	case 1:
		err = uploadV2Single(digests[0], exists)
	default:
		err = uploadV2Batch(digests, exists)
	}
	if err != nil {
		return err
	}
	return nil
}

// showWalletBalanceV1 returns the total balance of the primary dcrtimed wallet,
// in atoms.
func showWalletBalanceV1() error {
	c := newClient(*skipVerify)

	route := *host + v1.WalletBalanceRoute

	if *debug {
		fmt.Println(route)
	}

	url := fmt.Sprintf("%s?apitoken=%s", route, *apiToken)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	response, err := c.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if *printJSON {
		io.Copy(os.Stdout, response.Body)
		fmt.Printf("\n")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		e, err := getError(response.Body)
		if err != nil {
			return fmt.Errorf("Retrieve wallet balance failed: %v",
				response.Status)
		}
		return fmt.Errorf("Retrieve wallet balance failed - %v: %v",
			response.Status, e)
	}

	// Decode the response from dcrtimed
	var balance v1.WalletBalanceReply
	jsonDecoder := json.NewDecoder(response.Body)
	if err := jsonDecoder.Decode(&balance); err != nil {
		return fmt.Errorf("Could not decode WalletBalanceReply: %v", err)
	}

	if *verbose {
		fmt.Printf(
			"Wallet balance (atoms)\n"+
				"Spendable:   %v\n"+
				"Total:       %v\n"+
				"Unconfirmed: %v\n",
			balance.Spendable, balance.Total, balance.Unconfirmed)
	} else {
		fmt.Printf("Spendable wallet balance (atoms): %v\n", balance.Spendable)
	}

	return nil
}

// showWalletBalanceV2 returns the total balance of the primary dcrtimed wallet,
// in atoms.
func showWalletBalanceV2() error {
	c := newClient(*skipVerify)

	route := *host + v2.WalletBalanceRoute

	if *debug {
		fmt.Println(route)
	}

	url := fmt.Sprintf("%s?apitoken=%s", route, *apiToken)
	fmt.Println(url)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	response, err := c.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if *printJSON {
		io.Copy(os.Stdout, response.Body)
		fmt.Printf("\n")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		e, err := getError(response.Body)
		if err != nil {
			return fmt.Errorf("Retrieve wallet balance failed: %v",
				response.Status)
		}
		return fmt.Errorf("Retrieve wallet balance failed - %v: %v",
			response.Status, e)
	}

	// Decode the response from dcrtimed
	var balance v2.WalletBalanceReply
	jsonDecoder := json.NewDecoder(response.Body)
	if err := jsonDecoder.Decode(&balance); err != nil {
		return fmt.Errorf("Could not decode WalletBalanceReply: %v", err)
	}

	if *verbose {
		fmt.Printf(
			"Wallet balance (atoms)\n"+
				"Spendable:   %v\n"+
				"Total:       %v\n"+
				"Unconfirmed: %v\n",
			balance.Spendable, balance.Total, balance.Unconfirmed)
	} else {
		fmt.Printf("Spendable wallet balance (atoms): %v\n", balance.Spendable)
	}

	return nil
}

// lastAnchorV1 returns the last anchor information
// such as: tx, chain timestamp, block height & block hash
func lastAnchorV1() error {
	c := newClient(*skipVerify)
	route := *host + v1.LastAnchorRoute

	if *debug {
		fmt.Println(route)
	}

	request, err := http.NewRequest(http.MethodGet, route, nil)
	if err != nil {
		return err
	}

	response, err := c.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if *printJSON {
		io.Copy(os.Stdout, response.Body)
		fmt.Printf("\n")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		e, err := getError(response.Body)
		if err != nil {
			return fmt.Errorf("Retrieve last anchor info failed: %v",
				response.Status)
		}
		return fmt.Errorf("Retrieve last anchor info failed - %v: %v",
			response.Status, e)
	}

	// Decode the response from dcrtimed
	var anchor v1.LastAnchorReply
	jsonDecoder := json.NewDecoder(response.Body)
	if err := jsonDecoder.Decode(&anchor); err != nil {
		return fmt.Errorf("Could not decode LastAnchorReply: %v", err)
	}

	fmt.Printf(
		"ChainTimestamp:   %v\n"+
			"Transaction:      %v\n"+
			"Blockhash:        %v\n"+
			"Blockheight:      %v\n",
		anchor.ChainTimestamp, anchor.Transaction, anchor.BlockHash, anchor.BlockHeight)

	return nil
}

// lastAnchorV2 returns the last anchor information
// such as: tx, chain timestamp, block height & block hash
func lastAnchorV2() error {
	c := newClient(*skipVerify)
	route := *host + v2.LastAnchorRoute

	if *debug {
		fmt.Println(route)
	}

	request, err := http.NewRequest(http.MethodGet, route, nil)
	if err != nil {
		return err
	}

	response, err := c.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if *printJSON {
		io.Copy(os.Stdout, response.Body)
		fmt.Printf("\n")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		e, err := getError(response.Body)
		if err != nil {
			return fmt.Errorf("Retrieve last anchor info failed: %v",
				response.Status)
		}
		return fmt.Errorf("Retrieve last anchor info failed - %v: %v",
			response.Status, e)
	}

	// Decode the response from dcrtimed
	var anchor v2.LastAnchorReply
	jsonDecoder := json.NewDecoder(response.Body)
	if err := jsonDecoder.Decode(&anchor); err != nil {
		return fmt.Errorf("Could not decode LastAnchorReply: %v", err)
	}

	fmt.Printf(
		"ChainTimestamp:   %v\n"+
			"Transaction:      %v\n"+
			"Blockhash:        %v\n"+
			"Blockheight:      %v\n",
		anchor.ChainTimestamp, anchor.Transaction, anchor.BlockHash, anchor.BlockHeight)

	return nil
}

func lastDigestsV2(n int32) error {
	c := newClient(*skipVerify)
	route := *host + v2.LastDigestsRoute

	ld := v2.LastDigests{
		N: n,
	}

	ldj, err := json.Marshal(ld)
	if err != nil {
		return err
	}

	if *debug {
		fmt.Println(string(ldj))
		fmt.Println(route)
	}

	r, err := c.Post(route, "application/json",
		bytes.NewReader(ldj))

	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	if *printJSON {
		io.Copy(os.Stdout, r.Body)
		fmt.Printf("\n")
		return nil
	}

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("Retrieve last %d digests info failed: %v", n,
				r.Status)
		}
		return fmt.Errorf("Retrieve last %d digests info failed - %v: %v",
			n, r.Status, e)
	}

	// Decode the r from dcrtimed
	var ldr v2.LastDigestsReply
	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(&ldr); err != nil {
		return fmt.Errorf("Could not decode LastDigestsReply: %v", err)
	}

	fmt.Printf(
		"Digests:   %v\n",
		ldr.Digests)

	return nil
}

func hasDigestFlag() bool {
	return digest != nil && *digest != ""
}

func hasDigestsNumberFlag() bool {
	return digestsNumber != nil && *digestsNumber >= 0
}

// Ensures that there are no conflicting flags
func ensureFlagCompatibility() error {
	if *fileOnly && hasDigestFlag() {
		return fmt.Errorf(
			"-digest and -file flags cannot be used simultaneously")
	}

	return nil
}

// credentialsRequired determines if any of the flags
// require credentials to be provided.
func credentialsRequired() bool {
	return *balance
}

// loadCredentialsIfRequired checks if an apitoken is expected
// based on the provided command line flags.
func loadCredentialsIfRequired() error {
	if !credentialsRequired() {
		return nil
	}

	if *apiToken == "" {
		// Token not provided via command line. Try to load via config file.
		config, err := loadConfig()
		if err != nil {
			return fmt.Errorf("Attempt to load api token "+
				"from configuration file failed: %v", err)
		}

		*apiToken = config.APIToken
	}

	if *apiToken == "" {
		return fmt.Errorf("API token is required but was not provided")
	}

	return nil
}

func _main() error {
	flag.Parse()
	err := loadCredentialsIfRequired()
	if err != nil {
		return err
	}

	didRunCommand := false

	flagError := ensureFlagCompatibility()
	if flagError != nil {
		return flagError
	}

	var mainnetHost string
	var testnetHost string
	var mainnetPort string
	var testnetPort string
	var upload func([]string, map[string]string) error
	var download func([]string) error
	var showWalletBalance func() error
	var lastAnchorInfo func() error
	var lastDigestsInfo func(n int32) error

	// Set values according to selected API version. Default is v2.
	switch *apiVersion {
	case v1.APIVersion:
		mainnetHost = v1.DefaultMainnetTimeHost
		testnetHost = v1.DefaultTestnetTimeHost
		mainnetPort = v1.DefaultMainnetTimePort
		testnetPort = v1.DefaultTestnetTimePort
		upload = uploadV1
		download = downloadV1
		showWalletBalance = showWalletBalanceV1
		lastAnchorInfo = lastAnchorV1
	case v2.APIVersion:
		mainnetHost = v2.DefaultMainnetTimeHost
		testnetHost = v2.DefaultTestnetTimeHost
		mainnetPort = v2.DefaultMainnetTimePort
		testnetPort = v2.DefaultTestnetTimePort
		upload = uploadV2
		download = downloadV2Batch
		showWalletBalance = showWalletBalanceV2
		lastAnchorInfo = lastAnchorV2
		lastDigestsInfo = lastDigestsV2
	default:
		return fmt.Errorf("Invalid API version %v", *apiVersion)
	}

	if *host == "" {
		if *testnet {
			*host = testnetHost
		} else {
			*host = mainnetHost
		}
	}

	if *port == "" {
		if *testnet {
			*port = testnetPort
		} else {
			*port = mainnetPort
		}
	}

	*host = normalizeAddress(*host, *port)

	// Set port if not specified.
	u, err := url.Parse("https://" + *host)
	if err != nil {
		return err
	}
	*host = u.String()

	// Allow submitting a pre-calculated 256 bit digest from the command line,
	// rather than needing to hash a payload.
	if hasDigestFlag() {
		return upload([]string{*digest}, make(map[string]string))
	}

	// Print the wallet balance via privileged endpoint.
	if *balance {
		err := showWalletBalance()
		if err != nil {
			return err
		}

		didRunCommand = true
	}

	if *lastAnchor {
		err := lastAnchorInfo()
		if err != nil {
			return err
		}

		didRunCommand = true
	}

	// Print last n digests info
	if *lastDigests {
		if hasDigestsNumberFlag() {
			fmt.Println(int32(*digestsNumber))
			err := lastDigestsInfo(int32(*digestsNumber))
			if err != nil {
				return err
			}

			didRunCommand = true
		} else {
			return fmt.Errorf("digestsnumber should be a positive integer")
		}
	}

	// We attempt to open files first; if that doesn't work we treat the
	// args as digests or timestamps.  Digests and timestamps are sent to
	// the server for lookup.  Use fileOnly to override this behavior.
	var uploadArr []string
	var downloadArr []string
	exists := make(map[string]string) // [digest]filename
	for _, a := range flag.Args() {
		// Try to see if argument is a valid file.
		if isFile(a) || *fileOnly {
			d, err := util.DigestFile(a)
			if err != nil {
				return err
			}

			// Skip dups.
			if old, ok := exists[d]; ok {
				fmt.Printf("warning: duplicate digest "+
					"skipped: %v  %v -> %v\n", d, old, a)
				continue
			}
			exists[d] = a

			uploadArr = append(uploadArr, d)
			if *verbose {
				fmt.Printf("%v Upload %v\n", d, a)
			}
			continue
		}

		// Argument was not a file, try to see if it is a digest or
		// timestamp instead.
		if isDigest(a) || isTimestamp(a) {
			downloadArr = append(downloadArr, a)
			if *verbose {
				fmt.Printf("%-64v Verify\n", a)
			}
			continue
		}

		if isDir(a) {
			continue
		}

		return fmt.Errorf("%v is not a digest, timestamp or valid file",
			a)
	}

	if len(uploadArr) == 0 && len(downloadArr) == 0 && !didRunCommand {
		return fmt.Errorf("nothing to do")
	}

	if len(uploadArr) != 0 {
		err := upload(uploadArr, exists)
		if err != nil {
			return err
		}
	}

	if len(downloadArr) != 0 {
		err := download(downloadArr)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
