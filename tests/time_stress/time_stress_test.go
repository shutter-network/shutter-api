//go:build live

package time_stress

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
)

// TestTimeStress is the entry point for the stress runner. Behind the `live`
// build tag so `go test ./...` cannot start it by accident.
//
//	API_BASE_URL=https://shutter-api.chiado.staging.shutter.network \
//	API_SIGNER_ADDRESS=0xd150bbf86C686de1a25820A94c2C2397e0bC54ab \
//	API_AUTH_TOKEN=... \
//	STRESS_MODE=read-only WORKERS=20 TARGET_RPS=10 TEST_DURATION=10m \
//	go test -tags=live -run TestTimeStress -timeout 0 -v ./tests/time_stress
//
// -timeout 0 and -v are both required, for the same reasons as the continuous
// monitor: Go's default 10-minute test timeout would kill any real soak, and
// without -v no output is printed until the run ends.
func TestTimeStress(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	summary, err := Run(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Rounds == 0 {
		t.Fatal("no rounds ran — the run was stopped before the first round finished")
	}

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
