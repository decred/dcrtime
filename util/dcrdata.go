package util

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrdata/api/types/v5"
)

func extractNullDataMerkleRootV0(script []byte) []byte {
	// A null script is of the form:
	//  OP_RETURN <optional data>
	//
	// Thus, it can either be a single OP_RETURN or an OP_RETURN followed by a
	// canonical data push up to MaxDataCarrierSizeV0 bytes.
	//
	// When it houses a Merkle root, there will be a single push of 32 bytes.
	if len(script) == 34 &&
		script[0] == txscript.OP_RETURN &&
		script[1] == txscript.OP_DATA_32 {

		return script[2:34]
	}

	return nil
}

// VerifyAnchor verifies proof of existence of the supplied merkle root on the
// blockchain.
func VerifyAnchor(url, tx string, mr []byte) error {
	u := url + tx + "/out"
	r, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("HTTP Get: %v", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("invalid body: %v %v",
				r.StatusCode, body)
		}
		return fmt.Errorf("invalid dcrdata answer: %v %s",
			r.StatusCode, body)
	}

	var txOuts []types.TxOut
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&txOuts); err != nil {
		return err
	}

	var done bool
	for _, v := range txOuts {
		if !types.IsNullDataScript(v.ScriptPubKeyDecoded.Type) {
			continue
		}
		script, err := hex.DecodeString(v.ScriptPubKeyDecoded.Hex)
		if err != nil {
			return fmt.Errorf("invalid dcrdata script: %v", err)
		}
		data := extractNullDataMerkleRootV0(script)
		if data == nil {
			return fmt.Errorf("invalid script")
		}
		if !bytes.Equal(data, mr) {
			continue
		}

		// Everything is cool so mark it and break out
		done = true
		break
	}
	if !done {
		return fmt.Errorf("merkle root not found: tx %v merkle %x",
			tx, mr)
	}

	return nil
}
