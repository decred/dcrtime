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
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/dcrtime/util"
)

const (
	dcrtimeClientID = "dcrtime cli"
)

var (
	testnet   = flag.Bool("testnet", false, "Use testnet port")
	debug     = flag.Bool("debug", false, "Print JSON that is sent to server")
	printJson = flag.Bool("json", false, "Print JSON response from server")
	fileOnly  = flag.Bool("file", false, "Treat digests and timestamps "+
		"as file names")
	host    = flag.String("h", "", "Timestamping host")
	trial   = flag.Bool("t", false, "Trial run, don't contact server")
	verbose = flag.Bool("v", false, "Verbose")
	digest  = flag.String("digest", "", "Submit a raw 256 bit digest to anchor")
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
	return v1.RegexpSHA256.MatchString(digest)
}

// isTimestamp determines if a string is a valid UNIX timestamp.
func isTimestamp(timestamp string) bool {
	return v1.RegexpTimestamp.MatchString(timestamp)
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

func download(questions []string) error {
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

	if *debug {
		fmt.Println(string(b))
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	c := newClient(false)
	r, err := c.Post(*host+v1.VerifyRoute, "application/json",
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

	if *printJson {
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

func upload(digests []string, exists map[string]string) error {
	// batch uploads
	ts := v1.Timestamp{
		ID:      dcrtimeClientID,
		Digests: digests,
	}
	b, err := json.Marshal(ts)
	if err != nil {
		return err
	}

	if *debug {
		fmt.Println(string(b))
	}

	// If this is a trial run return.
	if *trial {
		return nil
	}

	c := newClient(false)
	r, err := c.Post(*host+v1.TimestampRoute, "application/json",
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

	if *printJson {
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
			fmt.Printf("%v OK     %v\n", tsReply.Digests[k], filename)
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

func hasDigestFlag() bool {
	return digest != nil && *digest != ""
}

func uploadDigest(digest string) error {
	return upload([]string{digest}, make(map[string]string))
}

// Ensures that there are no conflicting flags
func ensureFlagCompatibility() error {
	if *fileOnly && hasDigestFlag() {
		return fmt.Errorf("-digest and -file flags cannot be used simultaneously")
	}

	return nil
}

func _main() error {
	flag.Parse()

	flagError := ensureFlagCompatibility()
	if flagError != nil {
		return flagError
	}

	if *host == "" {
		if *testnet {
			*host = v1.DefaultTestnetTimeHost
		} else {
			*host = v1.DefaultMainnetTimeHost
		}
	}

	port := v1.DefaultMainnetTimePort
	if *testnet {
		port = v1.DefaultTestnetTimePort
	}

	*host = normalizeAddress(*host, port)

	// Set port if not specified.
	u, err := url.Parse("https://" + *host)
	if err != nil {
		return err
	}
	*host = u.String()

	// Allow submitting a pre-calculated 256 bit digest from the command line, rather than
	// needing to hash a payload.
	if hasDigestFlag() {
		return uploadDigest(*digest)
	}

	// We attempt to open files first; if that doesn't work we treat the
	// args as digests or timestamps.  Digests and timestamps are sent to
	// the server for lookup.  Use fileOnly to override this behavior.
	var uploads []string
	var downloads []string
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

			uploads = append(uploads, d)
			if *verbose {
				fmt.Printf("%v Upload %v\n", d, a)
			}
			continue
		}

		// Argument was not a file, try to see if it is a digest or
		// timestamp instead.
		if isDigest(a) || isTimestamp(a) {
			downloads = append(downloads, a)
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

	if len(uploads) == 0 && len(downloads) == 0 {
		return fmt.Errorf("nothing to do")
	}

	if len(uploads) != 0 {
		err := upload(uploads, exists)
		if err != nil {
			return err
		}
	}

	if len(downloads) != 0 {
		err := download(downloads)
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
