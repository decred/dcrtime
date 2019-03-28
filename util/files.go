package util

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// DigestFile returns the SHA256 of a file.
func DigestFile(filename string) (string, error) {
	h := sha256.New()
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
