// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	"path/filepath"

	"github.com/decred/dcrd/dcrutil/v2"

	flags "github.com/jessevdk/go-flags"
)

const (
	defaultConfigFilename = "dcrtime.conf"
)

var (
	defaultHomeDir    = cleanAndExpandPath(dcrutil.AppDataDir("dcrtime", false))
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
)

// config defines the configuration options for dcrtime.
//
// See loadConfig for details on the configuration load process.
type config struct {
	APIToken string `long:"apitoken" description:"Token for accessing privileged API resources"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Nothing to do when no path is given.
	if path == "" {
		return path
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
}

// loadConfig initializes and parses the config using a config file
func loadConfig() (*config, error) {
	// Default config.
	cfg := config{
		APIToken: "",
	}

	err := initHomeDirectory(defaultHomeDir)
	if err != nil {
		return nil, err
	}

	err = flags.IniParse(defaultConfigFile, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

// initHomeDirectory creates the home directory if it doesn't already exist.
func initHomeDirectory(homeDir string) error {
	funcName := "initHomeDirectory"
	err := os.MkdirAll(homeDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create home directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	return nil
}
