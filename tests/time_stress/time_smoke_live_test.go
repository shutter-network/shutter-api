//go:build live

package timestress

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTimeSmokeCases(t *testing.T) {
	loadDotEnv()

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Skipf("live env not configured: %v", err)
	}

	allCases, err := LoadCasesFromJSON(cfg.CasesFile)
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

	logf(cfg, "config api=%s poll=%ds/%ds verbose=%t offset=%s concurrency=%d cases=%d",
		cfg.APIBase, cfg.PollSeconds, cfg.PollInterval, cfg.Verbose,
		cfg.TimeDecryptionOffset, cfg.RegConcurrency, len(cases))

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
		filepath.Join("tests", "time_stress", ".env"),
		filepath.Join("..", "..", ".env"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
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
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
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
