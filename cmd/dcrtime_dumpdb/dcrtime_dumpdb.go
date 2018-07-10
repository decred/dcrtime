package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
)

var (
	defaultHomeDir = dcrutil.AppDataDir("dcrtimed", false)
	testnet        = flag.Bool("testnet", false, "Use testnet port")
	dumpJSON       = flag.Bool("json", false, "Dump JSON")
	restore        = flag.Bool("restore", false, "Restore backend, -destination is required")
	destination    = flag.String("destination", "", "Restore destination")
	fsRoot         = flag.String("source", defaultHomeDir, "Source directory")
)

func _main() error {
	flag.Parse()

	if *restore {
		if *destination == "" {
			return fmt.Errorf("-destination must be set")
		}
	}

	if *restore {
		// Restore
		fs, err := filesystem.NewRestore(*destination)
		if err != nil {
			return err
		}
		defer fs.Close()

		return fs.Restore(os.Stdin, true, *destination)
	}

	// Dump
	var root string
	if *testnet {
		root = filepath.Join(*fsRoot, "data", "testnet2")
	} else {
		root = filepath.Join(*fsRoot, "data", "mainnet")
	}

	fs, err := filesystem.NewDump(root)
	if err != nil {
		return err
	}
	defer fs.Close()

	return fs.Dump(os.Stdout, !*dumpJSON)
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
