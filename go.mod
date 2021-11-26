module github.com/decred/dcrtime

go 1.12

require (
	decred.org/dcrwallet v1.6.0
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/certgen v1.1.1
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/chaincfg/v3 v3.0.0
	github.com/decred/dcrd/dcrutil/v3 v3.0.0
	github.com/decred/dcrd/txscript/v3 v3.0.0
	github.com/decred/dcrd/wire v1.4.0
	github.com/decred/dcrdata/api/types/v5 v5.0.1
	github.com/decred/dcrtime/api/v2 v2.0.0
	github.com/decred/slog v1.1.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/jessevdk/go-flags v1.4.1-0.20200711081900-c17162fe8fd7
	github.com/jrick/logrotate v1.0.0
	github.com/robfig/cron v1.2.0
	github.com/syndtr/goleveldb v1.0.1-0.20200815110645-5c35d600f0ca
	google.golang.org/grpc v1.32.0
)

replace github.com/decred/dcrtime/api/v2 => ./api/v2
