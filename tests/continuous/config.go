// Package continuous runs the time-based decryption round against a deployed
// Shutter API, repeatedly, for a configurable duration. Each round registers an
// identity, encrypts a message to it, waits for the decryption timestamp, fetches
// the released key and decrypts — so a passing round proves the key is correct,
// not merely that one was returned.
//
// It is a black-box monitor: it talks to the deployed API over HTTPS and touches
// no internal packages.
package continuous

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Config is read entirely from the environment. APIBaseURL and SignerAddress have
// no defaults on purpose — a monitor that silently falls back to another network
// is worse than one that refuses to start.
type Config struct {
	APIBaseURL    string         // deployed API root, e.g. https://shutter-api.shutter.network
	SignerAddress common.Address // the API's own signer; identities derive from it
	AuthToken     string         // bearer token; empty means send no Authorization header

	Duration time.Duration // total run time; 0 runs until the process is stopped
	Interval time.Duration // gap between the start of one round and the next
	Lead     time.Duration // how far ahead of now to set the decryption timestamp

	PollInterval time.Duration // gap between get_decryption_key attempts
	PollTimeout  time.Duration // give up this long after the decryption timestamp

	// MetricsPort exposes /metrics for a vmagent to scrape, the same pattern the
	// keypers use. 0 disables the endpoint. instance/network/deployment labels are
	// applied by vmagent, not here.
	MetricsPort int
}

// LoadConfig reads configuration from the environment, applies defaults, and
// rejects anything that would make a run meaningless rather than merely wrong.
func LoadConfig() (Config, error) {
	c := Config{
		APIBaseURL:   strings.TrimSuffix(os.Getenv("API_BASE_URL"), "/"),
		AuthToken:    os.Getenv("API_AUTH_TOKEN"),
		MetricsPort:  9300,
		Interval:     time.Minute,
		Lead:         time.Minute,
		PollInterval: 2 * time.Second,
		PollTimeout:  2 * time.Minute,
	}

	if raw := os.Getenv("METRICS_PORT"); raw != "" {
		p, err := strconv.Atoi(raw)
		if err != nil {
			return c, fmt.Errorf("METRICS_PORT: %w", err)
		}
		if p < 0 || p > 65535 {
			return c, fmt.Errorf("METRICS_PORT must be between 0 and 65535, got %d", p)
		}
		c.MetricsPort = p
	}

	if c.APIBaseURL == "" {
		return c, fmt.Errorf("API_BASE_URL is required, e.g. https://shutter-api.shutter.network")
	}

	addr := os.Getenv("API_SIGNER_ADDRESS")
	if !common.IsHexAddress(addr) {
		return c, fmt.Errorf("API_SIGNER_ADDRESS is required and must be a hex address, got %q", addr)
	}
	c.SignerAddress = common.HexToAddress(addr)

	durations := []struct {
		env string
		dst *time.Duration
	}{
		{"TEST_DURATION", &c.Duration},
		{"ROUND_INTERVAL", &c.Interval},
		{"DECRYPTION_LEAD", &c.Lead},
		{"POLL_INTERVAL", &c.PollInterval},
		{"POLL_TIMEOUT", &c.PollTimeout},
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

	// A lead shorter than a few blocks means the registration may not be visible on
	// chain before the timestamp passes, which reports as a failure that isn't one.
	// Registrations become queryable roughly one block (~5s) after submission.
	if c.Lead < 15*time.Second {
		return c, fmt.Errorf("DECRYPTION_LEAD must be at least 15s, got %s", c.Lead)
	}
	if c.Duration < 0 {
		return c, fmt.Errorf("TEST_DURATION must not be negative, got %s", c.Duration)
	}
	// A round cannot finish sooner than Lead, and the loop won't start one it knows
	// cannot finish inside the run, so a Duration at or below Lead runs zero rounds.
	// Caught here rather than after startup: it is a configuration mistake, and the
	// symptom (a run that ends instantly having done nothing) does not look like one.
	if c.Duration > 0 && c.Duration <= c.Lead {
		return c, fmt.Errorf(
			"TEST_DURATION (%s) must be longer than DECRYPTION_LEAD (%s), since a round takes at least the lead to complete; try %s",
			c.Duration, c.Lead, 5*c.Lead)
	}
	if c.Interval <= 0 || c.PollInterval <= 0 || c.PollTimeout <= 0 {
		return c, fmt.Errorf("ROUND_INTERVAL, POLL_INTERVAL and POLL_TIMEOUT must all be positive")
	}

	// Interval is a minimum gap between round starts, not a fixed schedule. A round
	// takes at least Lead, so with Interval == Lead (the 1/min, 60s-lead case) rounds
	// run effectively back to back. Rounds never overlap: the monitor is sequential.

	return c, nil
}