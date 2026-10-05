// Package time_stress drives the time-based decryption endpoints of a deployed
// Shutter API at user-selected concurrency and arrival rate, so you can see how
// the API, keypers, and anything in front of them (such as a new RPC/WS
// loadbalancer in front of Gnosis / Chiado) behave under load without needing a
// dedicated traffic generator.
//
// Modes:
//
//   - "full"      — each worker runs the full round (register → encrypt → wait →
//     poll → decrypt → verify). Exercises every stage end-to-end,
//     but each round costs an on-chain registration tx on the API,
//     so sustained throughput is limited by the API's own tx path.
//   - "read-only" — a one-time setup registers a pool of identities and waits
//     for their keys. Workers then loop over the pool calling
//     get_data_for_encryption and get_decryption_key. Isolates
//     the read path without a per-round on-chain tx, so the main
//     thing moving is RPC/WS load through the LB.
//
// Like the continuous monitor this sits next to, it is a black-box runner that
// speaks only the public HTTP contract — no internal packages.
package time_stress

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type Mode string

const (
	ModeFull     Mode = "full"
	ModeReadOnly Mode = "read-only"
)

// Config is loaded entirely from the environment. APIBaseURL and SignerAddress
// have no defaults so a run cannot silently hit the wrong network.
type Config struct {
	APIBaseURL    string
	SignerAddress common.Address
	AuthToken     string

	Mode     Mode
	Workers  int           // bound on in-flight rounds
	TargetRPS float64      // 0 means uncapped — workers loop as fast as they can

	Duration time.Duration // 0 runs until the process is stopped

	// Full-mode knobs.
	Lead         time.Duration
	PollInterval time.Duration
	PollTimeout  time.Duration

	// Read-only knobs.
	PoolSize       int           // number of pre-registered identities to rotate over
	PoolSetupLead  time.Duration // decryption timestamp lead used while building the pool
	PoolSetupPoll  time.Duration // give up on pool setup after this long past the timestamp

	// HTTPTimeout bounds any single API call. Set generously — a loadbalancer
	// hiccup should surface as a slow request, not an immediate failure.
	HTTPTimeout time.Duration

	MetricsPort int
}

func LoadConfig() (Config, error) {
	c := Config{
		APIBaseURL:    strings.TrimSuffix(os.Getenv("API_BASE_URL"), "/"),
		AuthToken:     os.Getenv("API_AUTH_TOKEN"),
		Mode:          ModeFull,
		Workers:       4,
		TargetRPS:     0,
		Lead:          30 * time.Second,
		PollInterval: 2 * time.Second,
		PollTimeout:  2 * time.Minute,
		PoolSize:      10,
		PoolSetupLead: 45 * time.Second,
		PoolSetupPoll: 3 * time.Minute,
		HTTPTimeout:   30 * time.Second,
		MetricsPort:   9301,
	}

	if c.APIBaseURL == "" {
		return c, fmt.Errorf("API_BASE_URL is required, e.g. https://shutter-api.chiado.staging.shutter.network")
	}

	addr := os.Getenv("API_SIGNER_ADDRESS")
	if !common.IsHexAddress(addr) {
		return c, fmt.Errorf("API_SIGNER_ADDRESS is required and must be a hex address, got %q", addr)
	}
	c.SignerAddress = common.HexToAddress(addr)

	if raw := os.Getenv("STRESS_MODE"); raw != "" {
		m := Mode(strings.ToLower(raw))
		if m != ModeFull && m != ModeReadOnly {
			return c, fmt.Errorf("STRESS_MODE must be %q or %q, got %q", ModeFull, ModeReadOnly, raw)
		}
		c.Mode = m
	}

	ints := []struct {
		env string
		dst *int
	}{
		{"WORKERS", &c.Workers},
		{"POOL_SIZE", &c.PoolSize},
		{"METRICS_PORT", &c.MetricsPort},
	}
	for _, i := range ints {
		raw := os.Getenv(i.env)
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return c, fmt.Errorf("%s: %w", i.env, err)
		}
		*i.dst = v
	}

	if raw := os.Getenv("TARGET_RPS"); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return c, fmt.Errorf("TARGET_RPS: %w", err)
		}
		if v < 0 {
			return c, fmt.Errorf("TARGET_RPS must be >= 0, got %v", v)
		}
		c.TargetRPS = v
	}

	durations := []struct {
		env string
		dst *time.Duration
	}{
		{"TEST_DURATION", &c.Duration},
		{"DECRYPTION_LEAD", &c.Lead},
		{"POLL_INTERVAL", &c.PollInterval},
		{"POLL_TIMEOUT", &c.PollTimeout},
		{"POOL_SETUP_LEAD", &c.PoolSetupLead},
		{"POOL_SETUP_POLL", &c.PoolSetupPoll},
		{"HTTP_TIMEOUT", &c.HTTPTimeout},
	}
	for _, d := range durations {
		raw := os.Getenv(d.env)
		if raw == "" {
			continue
		}
		v, err := time.ParseDuration(raw)
		if err != nil {
			return c, fmt.Errorf("%s: %w", d.env, err)
		}
		*d.dst = v
	}

	if c.Workers <= 0 {
		return c, fmt.Errorf("WORKERS must be > 0, got %d", c.Workers)
	}
	if c.MetricsPort < 0 || c.MetricsPort > 65535 {
		return c, fmt.Errorf("METRICS_PORT must be between 0 and 65535, got %d", c.MetricsPort)
	}
	if c.Duration < 0 {
		return c, fmt.Errorf("TEST_DURATION must not be negative, got %s", c.Duration)
	}
	// Short leads make the full-round mode report false failures: the registration
	// has to be visible on chain before the timestamp passes, which takes roughly
	// one block (~5s on Gnosis / Chiado). 15s is the same floor the continuous
	// monitor enforces, and matches observed behaviour.
	if c.Mode == ModeFull && c.Lead < 15*time.Second {
		return c, fmt.Errorf("DECRYPTION_LEAD must be at least 15s, got %s", c.Lead)
	}
	if c.PollInterval <= 0 || c.PollTimeout <= 0 {
		return c, fmt.Errorf("POLL_INTERVAL and POLL_TIMEOUT must be positive")
	}
	if c.HTTPTimeout <= 0 {
		return c, fmt.Errorf("HTTP_TIMEOUT must be positive")
	}
	if c.Mode == ModeReadOnly {
		if c.PoolSize <= 0 {
			return c, fmt.Errorf("POOL_SIZE must be > 0, got %d", c.PoolSize)
		}
		if c.PoolSetupLead < 15*time.Second {
			return c, fmt.Errorf("POOL_SETUP_LEAD must be at least 15s, got %s", c.PoolSetupLead)
		}
		if c.PoolSetupPoll <= 0 {
			return c, fmt.Errorf("POOL_SETUP_POLL must be positive")
		}
	}

	return c, nil
}

func (c Config) String() string {
	rps := "uncapped"
	if c.TargetRPS > 0 {
		rps = fmt.Sprintf("%.2f", c.TargetRPS)
	}
	return fmt.Sprintf("mode=%s workers=%d rps=%s duration=%s base=%s", c.Mode, c.Workers, rps, durationOrForever(c.Duration), c.APIBaseURL)
}

func durationOrForever(d time.Duration) string {
	if d == 0 {
		return "unbounded"
	}
	return d.String()
}
