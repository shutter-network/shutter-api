package eventsmoke

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	APIBase           string
	RPCURL            string
	PrivateKey        string
	PlaygroundAddr    string
	DestAddr          string
	FromAddr          string
	TransferValue     int
	TTL               uint64
	PollSeconds       int
	PollInterval      int
	AuthHeader        string
	Verbose           bool
	WaitRegReceipt    bool
	RegistrationDelay time.Duration
	MaxConsecTimeouts int
	HTTPClient        *http.Client
	CasesFile         string
}

func LoadConfigFromEnv() (*Config, error) {
	apiBase, err := mustEnv("API_BASE_URL")
	if err != nil {
		return nil, err
	}
	rpcURL, err := mustEnv("RPC_URL")
	if err != nil {
		return nil, err
	}
	privateKey, err := mustEnv("PRIVATE_KEY")
	if err != nil {
		return nil, err
	}
	playground, err := mustEnv("PLAYGROUND_ADDR")
	if err != nil {
		return nil, err
	}
	dest, err := mustEnv("DEST_ADDR")
	if err != nil {
		return nil, err
	}

	transferValue := getInt("TRANSFER_VALUE", 2)
	ttl := getUint64("TTL", 120)
	pollSeconds := getInt("POLL_SECONDS", 130)
	pollInterval := getInt("POLL_INTERVAL", 2)
	verbose := getBool("VERBOSE", true)
	waitRegReceipt := getBool("WAIT_REGISTRATION_RECEIPT", false)
	regDelaySeconds := getInt("REGISTRATION_DELAY_SECONDS", 2)
	maxTimeouts := getInt("MAX_CONSEC_TIMEOUTS", 5)
	casesFile := getEnv("CASES_FILE", "testdata/cases.chiado.json")

	return &Config{
		APIBase:           strings.TrimRight(apiBase, "/"),
		RPCURL:            rpcURL,
		PrivateKey:        privateKey,
		PlaygroundAddr:    playground,
		DestAddr:          dest,
		FromAddr:          strings.TrimSpace(os.Getenv("FROM_ADDR")),
		TransferValue:     transferValue,
		TTL:               ttl,
		PollSeconds:       pollSeconds,
		PollInterval:      pollInterval,
		AuthHeader:        strings.TrimSpace(os.Getenv("AUTH_HEADER")),
		Verbose:           verbose,
		WaitRegReceipt:    waitRegReceipt,
		RegistrationDelay: time.Duration(regDelaySeconds) * time.Second,
		MaxConsecTimeouts: maxTimeouts,
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
		CasesFile:         casesFile,
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

func getUint64(k string, d uint64) uint64 {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	n, err := strconv.ParseUint(v, 10, 64)
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