module github.com/decred/dcrtime

go 1.12

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/certgen v1.1.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/chaincfg/v2 v2.3.0
	github.com/decred/dcrd/dcrutil/v2 v2.0.1
	github.com/decred/dcrd/txscript/v2 v2.1.0
	github.com/decred/dcrd/wire v1.3.0
	github.com/decred/dcrdata/api/types/v4 v4.0.4
	github.com/decred/dcrtime/api/v2 v2.0.0
	github.com/decred/dcrwallet/rpc/walletrpc v0.3.0
	github.com/decred/slog v1.0.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/robfig/cron v1.2.0
	github.com/syndtr/goleveldb v1.0.0
	google.golang.org/grpc v1.27.1
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/decred/dcrtime/api/v2 => ./api/v2
