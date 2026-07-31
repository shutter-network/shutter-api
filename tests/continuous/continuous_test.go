//go:build live

package continuous

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
)

// TestContinuous is the entry point for the monitor. It is behind the `live` build
// tag so `go test ./...` never starts a long-running loop by accident.
//
//	API_BASE_URL=https://shutter-api.shutter.network \
//	API_SIGNER_ADDRESS=0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc \
//	API_AUTH_TOKEN=... TEST_DURATION=26h \
//	go test -tags=live -run TestContinuous -timeout 0 -v ./tests/continuous
//
// -timeout 0 matters: Go's default 10-minute test timeout would kill any real run.
// -v matters too: without it `go test` buffers all output until the test finishes,
// so a 26-hour run would print nothing until the end.
func TestContinuous(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// SIGTERM (docker stop) and SIGINT end the run cleanly so the summary is printed
	// rather than lost.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	summary := Run(ctx, cfg, logger)

	// A backstop. The TEST_DURATION-vs-DECRYPTION_LEAD case is rejected by LoadConfig,
	// so reaching this means the run was cancelled before the first round completed.
	if summary.Rounds == 0 {
		t.Fatal("no rounds ran — the run was stopped before the first round finished")
	}

	// The test owns the pass/fail policy; the package only reports what happened.
	// A long soak may reasonably tolerate a transient failure or two.
	allowed := 0
	if raw := os.Getenv("ALLOWED_FAILURES"); raw != "" {
		allowed, err = strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("ALLOWED_FAILURES: %v", err)
		}
	}
	if summary.Failed > allowed {
		t.Errorf("%d of %d rounds failed (allowed %d)", summary.Failed, summary.Rounds, allowed)
	}
}