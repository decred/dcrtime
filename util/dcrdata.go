package util

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrdata/api/types/v4"
)

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
		data, err := txscript.PushedData(script)
		if err != nil {
			return fmt.Errorf("invalid script: %v", err)
		}
		if !bytes.Equal(data[0], mr) {
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
