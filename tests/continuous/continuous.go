package continuous

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"
)

// Summary aggregates a run. Returned rather than logged so a test can assert on it.
type Summary struct {
	Rounds  int
	Passed  int
	Failed  int
	Elapsed time.Duration

	Latencies []time.Duration // successful rounds only, in completion order
}

// Percentile returns the pth percentile release latency across successful rounds.
// Zero if there were none.
func (s Summary) Percentile(p float64) time.Duration {
	if len(s.Latencies) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(s.Latencies))
	copy(sorted, s.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (s Summary) String() string {
	return fmt.Sprintf("rounds=%d passed=%d failed=%d elapsed=%s p50=%s p95=%s max=%s",
		s.Rounds, s.Passed, s.Failed, s.Elapsed.Round(time.Second),
		s.Percentile(0.50).Round(time.Millisecond),
		s.Percentile(0.95).Round(time.Millisecond),
		s.Percentile(1.0).Round(time.Millisecond),
	)
}

// Run executes rounds until the configured duration elapses or the context is
// cancelled, and returns what happened.
//
// A failed round is recorded and the run continues. That is deliberate: this is
// built to run for a day, and one transient failure must not end it.
func Run(ctx context.Context, cfg Config, logger *log.Logger) Summary {
	c := newClient(cfg)

	reg, metrics := newCollectors()
	stopMetrics, metricsAddr, err := serveMetrics(cfg.MetricsPort, reg)
	if err != nil {
		// A bound port is a misconfiguration worth surfacing, but it must not stop a
		// run that would otherwise produce useful data.
		logger.Printf("metrics endpoint disabled: %v", err)
	}
	defer stopMetrics()

	start := time.Now()
	var deadline time.Time
	if cfg.Duration > 0 {
		deadline = start.Add(cfg.Duration)
	}

	logger.Printf("start base=%s addr=%s interval=%s lead=%s duration=%s metrics=%s",
		cfg.APIBaseURL, cfg.SignerAddress.Hex(),
		cfg.Interval, cfg.Lead, durationOrForever(cfg.Duration), metricsTarget(metricsAddr))

	summary := Summary{}

	for round := 1; ; round++ {
		if ctx.Err() != nil {
			break
		}
		// Stop before starting a round we know cannot finish inside the run.
		if !deadline.IsZero() && time.Now().Add(cfg.Lead).After(deadline) {
			break
		}

		roundStart := time.Now()
		res := RunRound(ctx, c, cfg, round)

		// A cancelled context is the run ending, not a failed round — don't record it.
		if ctx.Err() != nil {
			break
		}

		summary.Rounds++
		if res.Pass {
			summary.Passed++
			summary.Latencies = append(summary.Latencies, res.Latency)
		} else {
			summary.Failed++
		}
		logger.Println(res.String())
		metrics.observe(res)

		// Interval is a floor on the gap between round starts. If the round already
		// took longer, start the next one immediately.
		if wait := cfg.Interval - time.Since(roundStart); wait > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}

	summary.Elapsed = time.Since(start)
	logger.Printf("done %s", summary)
	return summary
}

func durationOrForever(d time.Duration) string {
	if d == 0 {
		return "unbounded"
	}
	return d.String()
}

func metricsTarget(addr string) string {
	if addr == "" {
		return "disabled"
	}
	return addr + "/metrics"
}