package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrtime/dcrtimed/backend/filesystem"
)

var (
	defaultHomeDir = dcrutil.AppDataDir("dcrtimed", false)
	fsRoot         = flag.String("d", defaultHomeDir, "Backend directory")
)

func _main() error {
	flag.Parse()

	return filesystem.DumpAll(*fsRoot)
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
