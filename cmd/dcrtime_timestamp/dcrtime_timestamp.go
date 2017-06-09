// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	fStr = "20060102.150405"
)

func _main() error {
	flag.Parse()

	for _, a := range flag.Args() {
		// Try number first
		ts, err := strconv.Atoi(a)
		if err == nil {
			fmt.Printf("%v\n", time.Unix(int64(ts),
				0).UTC().Format(fStr))
			continue
		}

		// Try timestam second
		timestamp, err := time.Parse(fStr, a)
		if err == nil {
			fmt.Printf("%v\n", timestamp.Unix())
			continue
		}

		fmt.Printf("unrecognized timestamp: %v\n", a)
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
