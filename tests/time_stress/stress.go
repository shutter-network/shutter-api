package time_stress

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Summary aggregates a run. Returned rather than logged so the test wrapper can
// assert on it.
type Summary struct {
	Mode     Mode
	Rounds   int
	Passed   int
	Failed   int
	Elapsed  time.Duration
	Latencies []time.Duration

	// StageDurations keeps every observed per-stage duration across the run, so
	// percentiles can be computed per stage rather than only overall.
	StageDurations map[string][]time.Duration
	FailuresByStage map[string]int
}

func (s Summary) percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// String renders a one-line overall summary. The per-stage breakdown is left to
// the caller — it is too long for a single line but useful at the end of a run.
func (s Summary) String() string {
	return fmt.Sprintf("mode=%s rounds=%d passed=%d failed=%d elapsed=%s p50=%s p95=%s p99=%s max=%s",
		s.Mode, s.Rounds, s.Passed, s.Failed, s.Elapsed.Round(time.Second),
		s.percentile(s.Latencies, 0.50).Round(time.Millisecond),
		s.percentile(s.Latencies, 0.95).Round(time.Millisecond),
		s.percentile(s.Latencies, 0.99).Round(time.Millisecond),
		s.percentile(s.Latencies, 1.0).Round(time.Millisecond),
	)
}

// StageReport returns a sorted multi-line breakdown of per-stage latency
// percentiles, suitable for printing once at the end of a run.
func (s Summary) StageReport() string {
	stages := make([]string, 0, len(s.StageDurations))
	for name := range s.StageDurations {
		stages = append(stages, name)
	}
	sort.Strings(stages)

	out := "per-stage latency:\n"
	for _, name := range stages {
		ds := s.StageDurations[name]
		if len(ds) == 0 {
			continue
		}
		out += fmt.Sprintf("  %-26s n=%d p50=%s p95=%s p99=%s max=%s\n",
			name, len(ds),
			s.percentile(ds, 0.50).Round(time.Millisecond),
			s.percentile(ds, 0.95).Round(time.Millisecond),
			s.percentile(ds, 0.99).Round(time.Millisecond),
			s.percentile(ds, 1.0).Round(time.Millisecond),
		)
	}
	if len(s.FailuresByStage) > 0 {
		out += "failures by stage:\n"
		keys := make([]string, 0, len(s.FailuresByStage))
		for k := range s.FailuresByStage {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out += fmt.Sprintf("  %-26s %d\n", k, s.FailuresByStage[k])
		}
	}
	return out
}

// Run executes the stress run until Duration elapses or ctx is cancelled.
//
// A failed round is recorded and the run continues: a stress run is interesting
// only in aggregate, and killing it on the first error loses the aggregate.
func Run(ctx context.Context, cfg Config, logger *log.Logger) (Summary, error) {
	c := newClient(cfg)
	reg, metrics := newCollectors()

	stopMetrics, metricsAddr, err := serveMetrics(cfg.MetricsPort, reg)
	if err != nil {
		logger.Printf("metrics endpoint disabled: %v", err)
	}
	defer stopMetrics()

	logger.Printf("start %s metrics=%s lead=%s poll_interval=%s poll_timeout=%s",
		cfg, metricsTarget(metricsAddr), cfg.Lead, cfg.PollInterval, cfg.PollTimeout)

	// Read-only mode needs a pre-registered pool. Setup can be slow (one tx per
	// identity plus one wait), so this happens inside Run so Duration starts
	// counting from the first actual read request, not from startup.
	var pool []poolEntry
	if cfg.Mode == ModeReadOnly {
		logger.Printf("read-only setup: registering %d identities, waiting for keys (lead=%s)…", cfg.PoolSize, cfg.PoolSetupLead)
		p, err := buildPool(ctx, c, cfg, logger)
		if err != nil {
			return Summary{Mode: cfg.Mode}, fmt.Errorf("pool setup: %w", err)
		}
		pool = p
		logger.Printf("read-only setup: pool ready, %d identities", len(pool))
	}

	// A token bucket for arrival-rate pacing. rate.Inf when TARGET_RPS is 0 so
	// Wait returns immediately and workers loop as fast as the API allows.
	limit := rate.Inf
	if cfg.TargetRPS > 0 {
		limit = rate.Limit(cfg.TargetRPS)
	}
	// Burst equal to Workers lets a cold start saturate the pool without pacing
	// stalling the first round of each worker.
	limiter := rate.NewLimiter(limit, cfg.Workers)

	start := time.Now()
	var deadline time.Time
	if cfg.Duration > 0 {
		deadline = start.Add(cfg.Duration)
	}

	// A single derived context ensures Duration bounds everything, including
	// workers blocked in poll or waiting on the limiter.
	runCtx := ctx
	if cfg.Duration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	// Rounds and completion are collected across workers; sync primitives bound
	// their visibility.
	var (
		mu      sync.Mutex
		summary = Summary{
			Mode:            cfg.Mode,
			StageDurations:  map[string][]time.Duration{},
			FailuresByStage: map[string]int{},
		}
	)
	var roundCounter atomic.Int64

	// Report in-flight through metrics so a dashboard can show saturation.
	var inFlight atomic.Int64

	wg := sync.WaitGroup{}
	for w := 1; w <= cfg.Workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				if err := limiter.Wait(runCtx); err != nil {
					return // ctx cancelled or deadline
				}
				if runCtx.Err() != nil {
					return
				}
				round := int(roundCounter.Add(1))

				metrics.inFlight.Set(float64(inFlight.Add(1)))

				var res Result
				switch cfg.Mode {
				case ModeFull:
					res = runFullRound(runCtx, c, cfg, workerID, round)
				case ModeReadOnly:
					entry := pool[(round-1)%len(pool)]
					res = runReadRound(runCtx, c, cfg, workerID, round, entry)
				}

				metrics.inFlight.Set(float64(inFlight.Add(-1)))

				// A cancelled context looks like a failure but is the run ending;
				// don't record it or metrics will claim a failure on every graceful
				// shutdown.
				if runCtx.Err() != nil && !res.Pass {
					return
				}

				mu.Lock()
				summary.Rounds++
				if res.Pass {
					summary.Passed++
					summary.Latencies = append(summary.Latencies, res.Latency)
				} else {
					summary.Failed++
					summary.FailuresByStage[res.Stage]++
				}
				for stage, d := range res.StageDurations {
					summary.StageDurations[stage] = append(summary.StageDurations[stage], d)
				}
				mu.Unlock()

				metrics.observe(res)
				logger.Println(res.String())
			}
		}(w)
	}

	wg.Wait()
	summary.Elapsed = time.Since(start)
	logger.Printf("done %s", summary)
	logger.Printf("%s", summary.StageReport())
	return summary, nil
}

func metricsTarget(addr string) string {
	if addr == "" {
		return "disabled"
	}
	return addr + "/metrics"
}
