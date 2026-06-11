package timestress

import (
	"fmt"
	"time"
)

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
