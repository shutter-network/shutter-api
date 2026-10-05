# Time-based API stress runner.
#
# Built by the compose file in this directory, which sets the repository root as
# the build context because the Go module lives there. To build it by hand:
#
#   docker build -f tests/time_stress/Dockerfile -t shutter-api-time-stress .
#
# The runner is a Go test rather than a separate binary, same as the continuous
# monitor. `go test -c` compiles the test into a standalone binary, so a compile
# error fails the image build rather than the container three seconds after it
# starts.
FROM golang:1.24-alpine AS build

# blst, which shcrypto's BLS12-381 operations sit on, is cgo. Without a C
# toolchain its cgo files are dropped from the build and the pure-Go files that
# reference them fail to compile ("undefined: Message"). Same reason the API's
# own Dockerfile installs this.
RUN apk add --no-cache build-base

WORKDIR /src

# Dependencies first, so editing source doesn't invalidate the module cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go test -c -tags=live -o /stress ./tests/time_stress

FROM alpine:3.20

# Required for HTTPS to the API.
RUN apk add --no-cache ca-certificates

COPY --from=build /stress /stress

# `go test -c` produces a binary that takes the same flags as `go test`, prefixed
# with `-test.`:
#   -test.timeout 0  disables Go's default 10-minute timeout, which would kill
#                    any real soak.
#   -test.v          disables output buffering; without it nothing is printed
#                    until the run ends, so a long run would look silent.
ENTRYPOINT ["/stress", "-test.run", "TestTimeStress", "-test.timeout", "0", "-test.v"]
