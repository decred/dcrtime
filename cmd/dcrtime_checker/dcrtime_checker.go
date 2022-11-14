package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	v1 "github.com/decred/dcrtime/api/v1"
	v2 "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/dcrtime/util"
)

var (
	proof       = flag.String("p", "", "Proof file")
	file        = flag.String("f", "", "Original file")
	dcrdataHost = flag.String("h", "", "dcrdata host")
	testnet     = flag.Bool("testnet", false, "Use testnet port")
	verbose     = flag.Bool("v", false, "Verbose")
	apiVersion  = flag.Int("api", v2.APIVersion,
		"Inform the API version to be used by the cli (1 or 2)")
)

func verifyV2(digest string, fProof *os.File) error {
	var vr v2.VerifyBatchReply
	decoder := json.NewDecoder(fProof)
	if err := decoder.Decode(&vr); err != nil {
		return fmt.Errorf("Could node decode VerifyBatchReply: %v", err)
	}

	// Ensure file digest exists in the proof and that the saved answer was
	// correct
	found := -1
	for k, v := range vr.Digests {
		if v.Digest != digest {
			continue
		}

		found = k
		break
	}
	if found == -1 {
		return fmt.Errorf("file digest not found in proof")
	}
	v := vr.Digests[found]

	// Verify result of matching digest
	if _, ok := v2.Result[v.Result]; !ok {
		return fmt.Errorf("%v invalid error code %v", v.Digest,
			v.Result)
	}

	// Verify merkle path.
	root, err := merkle.VerifyAuthPath(&v.ChainInformation.MerklePath)
	if err != nil {
		if err != merkle.ErrEmpty {
			return fmt.Errorf("%v invalid auth path %v",
				v.Digest, err)
		}
		return fmt.Errorf("%v Not anchored", v.Digest)
	}

	// Verify merkle root.
	merkleRoot, err := hex.DecodeString(v.ChainInformation.MerkleRoot)
	if err != nil {
		return fmt.Errorf("invalid merkle root: %v", err)
	}
	// This is silly since we check against returned root.
	if !bytes.Equal(root[:], merkleRoot) {
		return fmt.Errorf("%v invalid merkle root", v.Digest)
	}

	// If we made it here we have a valid proof
	if *verbose {
		fmt.Printf("%v  Proof  OK\n", digest)
	}

	// Verify against dcrdata
	err = util.VerifyAnchor(*dcrdataHost,
		vr.Digests[found].ChainInformation.Transaction, root[:])
	if err != nil {
		return err
	}

	if *verbose {
		fmt.Printf("%v  Anchor OK\n", digest)
	}

	return nil
}

func verifyV1(digest string, fProof *os.File) error {
	var vr v1.VerifyReply
	decoder := json.NewDecoder(fProof)
	if err := decoder.Decode(&vr); err != nil {
		return fmt.Errorf("Could node decode VerifyReply: %v", err)
	}

	// Ensure file digest exists in the proof and that the saved answer was
	// correct
	found := -1
	for k, v := range vr.Digests {
		if v.Digest != digest {
			continue
		}

		found = k
		break
	}
	if found == -1 {
		return fmt.Errorf("file digest not found in proof")
	}
	v := vr.Digests[found]

	// Verify result of matching digest
	if _, ok := v1.Result[v.Result]; !ok {
		return fmt.Errorf("%v invalid error code %v", v.Digest,
			v.Result)
	}

	// Verify merkle path.
	root, err := merkle.VerifyAuthPath(&v.ChainInformation.MerklePath)
	if err != nil {
		if err != merkle.ErrEmpty {
			return fmt.Errorf("%v invalid auth path %v",
				v.Digest, err)
		}
		return fmt.Errorf("%v Not anchored", v.Digest)
	}

	// Verify merkle root.
	merkleRoot, err := hex.DecodeString(v.ChainInformation.MerkleRoot)
	if err != nil {
		return fmt.Errorf("invalid merkle root: %v", err)
	}
	// This is silly since we check against returned root.
	if !bytes.Equal(root[:], merkleRoot) {
		return fmt.Errorf("%v invalid merkle root", v.Digest)
	}

	// If we made it here we have a valid proof
	if *verbose {
		fmt.Printf("%v  Proof  OK\n", digest)
	}

	// Verify against dcrdata
	err = util.VerifyAnchor(*dcrdataHost,
		vr.Digests[found].ChainInformation.Transaction, root[:])
	if err != nil {
		return err
	}

	if *verbose {
		fmt.Printf("%v  Anchor OK\n", digest)
	}

	return nil
}

func _main() error {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dcrtime_checker [-h {dcrdatahost}|"+
			"-testnet|-v] -f {file} -p {proof}\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var verify func(string, *os.File) error

	// Set values according to selected api version.
	switch *apiVersion {
	case v1.APIVersion:
		verify = verifyV1
	case v2.APIVersion:
		verify = verifyV2
	default:
		return fmt.Errorf("Invalid API version %v", *apiVersion)
	}

	// require -f
	if *file == "" {
		return fmt.Errorf("must provide -f")
	}

	// require -p
	if *proof == "" {
		return fmt.Errorf("must provide -p")
	}

	// Handle dcrtime host
	if *dcrdataHost == "" {
		if *testnet {
			*dcrdataHost = "https://testnet.dcrdata.org/api/tx/"
		} else {
			*dcrdataHost = "https://explorer.dcrdata.org/api/tx/"
		}
	} else {
		if !strings.HasSuffix(*dcrdataHost, "/") {
			*dcrdataHost += "/"
		}
	}

	// Ensure proof looks correct
	fProof, err := os.Open(*proof)
	if err != nil {
		return err
	}

	// Get file digest
	d, err := util.DigestFile(*file)
	if err != nil {
		return err
	}

	if *verbose {
		fmt.Printf("%v  %v\n", d, *file)
	}

	err = verify(d, fProof)
	if err != nil {
		return err
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
