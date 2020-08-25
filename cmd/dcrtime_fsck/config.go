// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"path/filepath"

	"github.com/jessevdk/go-flags"
)

const defaultConfigFilename = "dcrtimed.conf"

var (
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultBackend    = "filesystem"
)

// config defines the configuration options for dcrtime_fsck
//
// See loadConfig for details on the configuration load process.
type config struct {
	HomeDir           string   `short:"A" long:"appdata" description:"Path to application home directory"`
	ShowVersion       bool     `short:"V" long:"version" description:"Display version information and exit"`
	ConfigFile        string   `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir           string   `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir            string   `long:"logdir" description:"Directory to log output."`
	TestNet           bool     `long:"testnet" description:"Use the test network"`
	SimNet            bool     `long:"simnet" description:"Use the simulation test network"`
	Profile           string   `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	CPUProfile        string   `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	MemProfile        string   `long:"memprofile" description:"Write mem profile to the specified file"`
	DebugLevel        string   `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Listeners         []string `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 49152, testnet: 59152)"`
	WalletHost        string   `long:"wallethost" description:"Hostname for wallet server"`
	WalletCert        string   `long:"walletcert" description:"Certificate path for wallet server"`
	WalletPassphrase  string   `long:"walletpassphrase" description:"Passphrase for wallet server"`
	Version           string
	HTTPSCert         string   `long:"httpscert" description:"File containing the https certificate file"`
	HTTPSKey          string   `long:"httpskey" description:"File containing the https certificate key"`
	StoreHost         string   `long:"storehost" description:"Enable proxy mode - send requests to the specified ip:port"`
	StoreCert         string   `long:"storecert" description:"File containing the https certificate file for storehost"`
	EnableCollections bool     `long:"enablecollections" description:"Allow clients to query collection timestamps."`
	APITokens         []string `long:"apitoken" description:"Token used to grant access to privileged API resources"`
	APIVersions       string   `long:"apiversions" description:"Enables API versions on the daemon"`
	Backend           string   `long:"backend" description:"Sets the cache layer type 'filesystem'/'postgres'"`
	PostgresHost      string   `long:"postgreshost" description:"Postgres ip:port"`
	PostgresRootCert  string   `long:"postgresrootcert" description:"File containing the CA certificate for postgres"`
	PostgresCert      string   `long:"postgrescert" description:"File containing the dcrtimed client certificate for postgres"`
	PostgresKey       string   `long:"postgreskey" description:"File containing the dcrtimed client certificate key for postgres"`
}

// loadConfig initializes and parses the config using a config file
func loadConfig() (*config, error) {
	// Default config.
	cfg := config{
		Backend: defaultBackend,
	}

	err := flags.IniParse(defaultConfigFile, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
