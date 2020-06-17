#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. gofmt         (http://golang.org/cmd/gofmt/)
# 2. go vet        (http://golang.org/cmd/vet)
# 3. gosimple      (https://github.com/dominikh/go-simple)
# 4. unconvert     (https://github.com/mdempsky/unconvert)
# 5. ineffassign   (https://github.com/gordonklaus/ineffassign)
# 6. race detector (http://blog.golang.org/race-detector)
# 7. test coverage (http://blog.golang.org/cover)

set -ex

# run tests
env GORACE="halt_on_error=1" go test -race ./...

# run `go mod download` and `go mod tidy` and fail if the git status of
# go.mod and/or go.sum changes
MOD_STATUS=$(git status --porcelain go.mod go.sum)
go mod download
go mod tidy
UPDATED_MOD_STATUS=$(git status --porcelain go.mod go.sum)
if [ "$UPDATED_MOD_STATUS" != "$MOD_STATUS" ]; then
  echo "Running `go mod tidy` modified go.mod and/or go.sum"
  exit 1
fi

# golangci-lint (github.com/golangci/golangci-lint) is used to run each each
# static checker.

# check linters
golangci-lint run --disable-all --deadline=10m \
  --enable=gofmt \
  --enable=vet \
  --enable=gosimple \
  --enable=unconvert \
  --enable=ineffassign
