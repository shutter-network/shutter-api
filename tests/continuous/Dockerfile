# Continuous round monitor for the Shutter API.
#
# Built by the compose file in this directory, which sets the repository root as the
# build context because the Go module lives there. To build it by hand:
#
#   docker build -f tests/continuous/Dockerfile -t shutter-api-continuous .
#
# The monitor is a Go test rather than a separate binary, so the repo needs no second
# entry point. `go test -c` compiles that test into a standalone binary, which keeps
# this a conventional build: a compile error fails the image build rather than the
# container three seconds after it starts.
#
# Floats on the 1.24 minor rather than pinning a patch: the latest 1.24.x is always at
# or ahead of the `toolchain` directive in go.mod, so this cannot fall behind and there
# is nothing to keep in sync by hand. Only the major.minor needs changing, and that is
# forced by go.mod rather than left to memory.
FROM golang:1.24-alpine AS build

# blst, which shcrypto's BLS12-381 operations sit on, is cgo. Without a C toolchain its
# cgo files are dropped from the build and the pure-Go files that reference them fail to
# compile ("undefined: Message"). Same reason the API's own Dockerfile installs this.
RUN apk add --no-cache build-base

WORKDIR /src

# Dependencies first, so editing source doesn't invalidate the module cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go test -c -tags=live -o /monitor ./tests/continuous

FROM alpine:3.20

# Required for HTTPS to the API. Without it every request fails with an x509 error.
RUN apk add --no-cache ca-certificates

COPY --from=build /monitor /monitor

# A compiled test binary takes the same flags as `go test`, prefixed with `-test.`:
#
#   -test.timeout 0  disables Go's default 10-minute timeout, which would otherwise
#                    kill any real run
#   -test.v          disables output buffering; without it nothing is printed until
#                    the run ends, so a 26-hour run would look silent
ENTRYPOINT ["/monitor", "-test.run", "TestContinuous", "-test.timeout", "0", "-test.v"]