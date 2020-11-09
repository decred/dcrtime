package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
)

var (
	defaultHomeDir = dcrutil.AppDataDir("dcrtimed", false)

	file        = flag.String("file", "", "journal of modifications if used (will be written despite -fix)")
	fix         = flag.Bool("fix", false, "Try to correct correctable failures")
	dcrdataHost = flag.String("host", "", "dcrdata block explorer")
	printHashes = flag.Bool("printhashes", false, "Print all hashes")
	fsRoot      = flag.String("source", "", "Source directory")
	testnet     = flag.Bool("testnet", false, "Use testnet port")
	verbose     = flag.Bool("v", false, "Print more information during run")
)

func _main() error {
	flag.Parse()

	root := *fsRoot
	if root == "" {
		root = filepath.Join(defaultHomeDir, "data")
		if *testnet {
			root = filepath.Join(root, chaincfg.TestNet3Params().Name)
		} else {
			root = filepath.Join(root, chaincfg.MainNetParams().Name)
		}
	}

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

	fmt.Printf("=== Root: %v\n", root)

	fs, err := filesystem.NewDump(root)
	if err != nil {
		return err
	}
	defer fs.Close()

	return fs.Fsck(&backend.FsckOptions{
		Verbose:     *verbose,
		PrintHashes: *printHashes,
		Fix:         *fix,
		URL:         *dcrdataHost,
		File:        *file,
	})
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
