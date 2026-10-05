package time_stress

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collectors are the stress runner's metrics.
//
// instance / network / deployment labels are expected to come from the vmagent
// that scrapes this endpoint, matching the keyper and continuous-monitor setup.
// Mode is a run-wide label and applied at construction time rather than at
// every observe call, so it is always consistent with the Config that produced
// it.
type collectors struct {
	rounds        *prometheus.CounterVec // result=pass|fail
	failures      *prometheus.CounterVec // stage=...
	roundLatency  prometheus.Histogram
	stageLatency  *prometheus.HistogramVec // stage=...
	inFlight      prometheus.Gauge
	lastSuccess   prometheus.Gauge
}

func newCollectors() (*prometheus.Registry, *collectors) {
	// Round-latency buckets are wider than continuous's because read-only mode
	// is often sub-second while full-round mode is dominated by DECRYPTION_LEAD
	// plus release latency.
	roundBuckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120}
	// Per-stage buckets focus on the sub-second range, which is where loadbalancer
	// pressure or RPC saturation first shows up.
	stageBuckets := []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30}

	c := &collectors{
		rounds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "rounds_total",
			Help:      "Completed stress rounds by outcome.",
		}, []string{"result"}),

		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "round_failures_total",
			Help:      "Failed rounds by the stage that broke.",
		}, []string{"stage"}),

		roundLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "round_latency_seconds",
			Help:      "End-to-end round latency. Full-mode: release latency past the decryption timestamp. Read-only mode: total time of the two read calls.",
			Buckets:   roundBuckets,
		}),

		stageLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "stage_latency_seconds",
			Help:      "Per-stage latency. Lets you tell a slow register from a slow poll.",
			Buckets:   stageBuckets,
		}, []string{"stage"}),

		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "in_flight_rounds",
			Help:      "Rounds currently executing. Tracks worker saturation.",
		}),

		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shutter_api",
			Subsystem: "time_stress",
			Name:      "last_success_timestamp_seconds",
			Help:      "Unix time of the most recent successful round.",
		}),
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(c.rounds, c.failures, c.roundLatency, c.stageLatency, c.inFlight, c.lastSuccess)

	// Initialise known label values so series exist from the first scrape, otherwise
	// "no failures yet" and "runner not scraped" produce identical gaps.
	c.rounds.WithLabelValues("pass").Add(0)
	c.rounds.WithLabelValues("fail").Add(0)
	for _, stage := range Stages {
		c.stageLatency.WithLabelValues(stage)
	}

	return reg, c
}

func (c *collectors) observe(res Result) {
	if res.Pass {
		c.rounds.WithLabelValues("pass").Inc()
		c.roundLatency.Observe(res.Latency.Seconds())
		c.lastSuccess.Set(float64(time.Now().Unix()))
	} else {
		c.rounds.WithLabelValues("fail").Inc()
		c.failures.WithLabelValues(res.Stage).Inc()
	}
	for stage, d := range res.StageDurations {
		c.stageLatency.WithLabelValues(stage).Observe(d.Seconds())
	}
}

func serveMetrics(port int, reg *prometheus.Registry) (stop func(), addr string, err error) {
	if port == 0 {
		return func() {}, "", nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		if e := srv.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errc <- e
		}
	}()
	// Short delay so a bound-port misconfig surfaces at startup, not as a silent
	// missing scrape target later.
	select {
	case e := <-errc:
		return func() {}, "", e
	case <-time.After(200 * time.Millisecond):
	}

	stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return stop, srv.Addr, nil
}
