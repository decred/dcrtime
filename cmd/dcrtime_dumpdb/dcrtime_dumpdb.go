package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/chaincfg/v2"
	"github.com/decred/dcrd/dcrutil/v2"
	"github.com/decred/dcrtime/dcrtimed/backend"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
	"github.com/decred/dcrtime/dcrtimed/backend/postgres"
)

var (
	defaultHomeDir = dcrutil.AppDataDir("dcrtimed", false)

	destination = flag.String("destination", "", "Restore destination")
	dumpJSON    = flag.Bool("json", false, "Dump JSON")
	restore     = flag.Bool("restore", false, "Restore backend, -destination is required")
	fsRoot      = flag.String("source", "", "Source directory")
	testnet     = flag.Bool("testnet", false, "Use testnet port")
)

func _main() error {
	flag.Parse()

	loadedCfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}

	root := *fsRoot
	if root == "" {
		root = filepath.Join(defaultHomeDir, "data")
		if *testnet {
			root = filepath.Join(root, chaincfg.TestNet3Params().Name)
		} else {
			root = filepath.Join(root, chaincfg.MainNetParams().Name)
		}
	}

	var b backend.Backend
	switch (*loadedCfg).Backend {
	case "filesystem":
		if *restore {
			if *destination == "" {
				return fmt.Errorf("-destination must be set")
			}
			b, err = filesystem.NewRestore(*destination)
			break
		}
		b, err = filesystem.NewDump(root)
		if !*dumpJSON {
			fmt.Printf("=== Root: %v\n", root)
		}
	case "postgres":
		var net string
		switch loadedCfg.TestNet {
		case true:
			net = "testnet"
		default:
			net = "mainnet"
		}
		b, err = postgres.NewDB(loadedCfg.PostgresHost,
			net,
			loadedCfg.PostgresRootCert,
			loadedCfg.PostgresCert,
			loadedCfg.PostgresKey)
	default:
		err = fmt.Errorf("Unsupported backend type: %v", (*loadedCfg).Backend)
	}
	if err != nil {
		return err
	}
	defer b.Close()

	if *restore {
		return b.Restore(os.Stdin, true, *destination)
	}
	return b.Dump(os.Stdout, !*dumpJSON)
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
