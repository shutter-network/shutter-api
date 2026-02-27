package eventsmoke

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	txHashRe = regexp.MustCompile(`0x[0-9a-fA-F]{64}`)
	addrRe   = regexp.MustCompile(`0x[0-9a-fA-F]{40}`)
)

func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("%s %s: timeout", name, strings.Join(args, " "))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func resolveFromAddress(privateKey string) (string, error) {
	out, err := runCmd("cast", "wallet", "address", "--private-key", privateKey)
	if err != nil {
		return "", err
	}
	addr := addrRe.FindString(out)
	if addr == "" {
		return "", fmt.Errorf("could not parse address from cast output: %s", strings.TrimSpace(out))
	}
	return addr, nil
}

func logf(cfg *Config, format string, args ...any) {
	if !cfg.Verbose {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Printf("[%s] %s\n", ts, fmt.Sprintf(format, args...))
}

func shortHex(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 0, 64)
		return n
	default:
		return 0
	}
}