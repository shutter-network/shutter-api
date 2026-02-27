//go:build live

package eventsmoke

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEventSmokeCases(t *testing.T) {
	loadDotEnv()

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Skipf("live env not configured: %v", err)
	}

	from := strings.TrimSpace(cfg.FromAddr)
	if from == "" {
		from, err = resolveFromAddress(cfg.PrivateKey)
		if err != nil {
			t.Fatalf("resolve from address: %v", err)
		}
	}

	vars := map[string]string{
		"FROM_ADDR":       from,
		"DEST_ADDR":       cfg.DestAddr,
		"TRANSFER_VALUE":  strconv.Itoa(cfg.TransferValue),
		"PLAYGROUND_ADDR": cfg.PlaygroundAddr,
		"TTL":             strconv.FormatUint(cfg.TTL, 10),
	}

	allCases, err := LoadCasesFromJSON(cfg.CasesFile, vars)
	if err != nil {
		t.Fatalf("load cases: %v", err)
	}

	cases, err := FilterCases(allCases, os.Getenv("CASES"))
	if err != nil {
		t.Fatalf("filter cases: %v", err)
	}
	if len(cases) == 0 {
		t.Fatalf("no test cases selected")
	}

	logf(cfg, "config api=%s rpc=%s playground=%s ttl=%d poll=%ds/%ds verbose=%t cases=%d",
		cfg.APIBase, cfg.RPCURL, cfg.PlaygroundAddr, cfg.TTL, cfg.PollSeconds, cfg.PollInterval, cfg.Verbose, len(cases))

	for _, tc := range cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("%s", tc.Description)
			r := runCase(cfg, tc)
			if r.Status != "PASS" {
				t.Fatalf("%s", r.Reason)
			}
			t.Logf("pass: %s", r.Reason)
		})
	}
}

func loadDotEnv() {
	candidates := []string{
		".env",
		filepath.Join("tests", "integration", "event_smoke", ".env"),
		filepath.Join("..", "..", "..", ".env"),
	}

	existing := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		}
	}

	if len(existing) > 0 {
		for _, p := range existing {
			_ = loadEnvFile(p)
		}
	}
}

func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return sc.Err()
}