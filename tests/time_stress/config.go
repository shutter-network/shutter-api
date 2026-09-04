package timestress

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	APIBase              string
	PollSeconds          int
	PollInterval         int
	AuthHeader           string
	Verbose              bool
	MaxConsecTimeouts    int
	HTTPClient           *http.Client
	CasesFile            string
	TimeDecryptionOffset time.Duration
	RegConcurrency       int
	RegistrationDelay    time.Duration
}

func LoadConfigFromEnv() (*Config, error) {
	apiBase, err := mustEnv("API_BASE_URL")
	if err != nil {
		return nil, err
	}

	pollSeconds := getInt("POLL_SECONDS", 130)
	pollInterval := getInt("POLL_INTERVAL", 2)
	verbose := getBool("VERBOSE", true)
	maxTimeouts := getInt("MAX_CONSEC_TIMEOUTS", 5)
	casesFile := getEnv("CASES_FILE", "testdata/cases.json")
	timeDecryptionOffsetSeconds := getInt("TIME_DECRYPTION_OFFSET_SECONDS", 90)
	regConcurrency := getInt("REG_CONCURRENCY", 1)
	regDelaySeconds := getInt("REGISTRATION_DELAY_SECONDS", 2)

	return &Config{
		APIBase:              strings.TrimRight(apiBase, "/"),
		PollSeconds:          pollSeconds,
		PollInterval:         pollInterval,
		AuthHeader:           strings.TrimSpace(os.Getenv("AUTH_HEADER")),
		Verbose:              verbose,
		MaxConsecTimeouts:    maxTimeouts,
		HTTPClient:           &http.Client{Timeout: 5 * time.Second},
		CasesFile:            casesFile,
		TimeDecryptionOffset: time.Duration(timeDecryptionOffsetSeconds) * time.Second,
		RegConcurrency:       regConcurrency,
		RegistrationDelay:    time.Duration(regDelaySeconds) * time.Second,
	}, nil
}

func mustEnv(k string) (string, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return "", fmt.Errorf("missing required env var %s", k)
	}
	return v, nil
}

func getEnv(k, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func getInt(k string, d int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func getBool(k string, d bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "" {
		return d
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return d
	}
}
