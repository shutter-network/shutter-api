package continuous

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collectors holds the monitor's metrics.
//
// Labels here are semantic only. instance, network, deployment and
// deployment_type are applied by the vmagent that scrapes this endpoint, exactly as
// they are for keypers — duplicating them in the application would produce two
// competing sources of truth for the same label.
type collectors struct {
	rounds      *prometheus.CounterVec // result="pass"|"fail"
	failures    *prometheus.CounterVec // stage=... — which step broke
	latency     prometheus.Histogram
	lastSuccess prometheus.Gauge
}

func newCollectors() (*prometheus.Registry, *collectors) {
	c := &collectors{
		rounds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shutter_api",
			Subsystem: "continuous",
			Name:      "rounds_total",
			Help:      "Completed rounds by outcome.",
		}, []string{"result"}),

		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shutter_api",
			Subsystem: "continuous",
			Name:      "round_failures_total",
			Help:      "Failed rounds by the stage that broke.",
		}, []string{"stage"}),

		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "shutter_api",
			Subsystem: "continuous",
			Name:      "release_latency_seconds",
			Help:      "Delay between the decryption timestamp and the key becoming available.",
			// Tuned to observed behaviour: keys land within a couple of seconds, and
			// the poll gives up at POLL_TIMEOUT (2m by default).
			Buckets: []float64{0.5, 1, 2, 3, 5, 8, 15, 30, 60, 120},
		}),

		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shutter_api",
			Subsystem: "continuous",
			Name:      "last_success_timestamp_seconds",
			Help:      "Unix time of the last round that completed and decrypted successfully.",
		}),
	}

	// A dedicated registry rather than the default one, so this exposes only the
	// monitor's own series and nothing a transitively imported package registered.
	reg := prometheus.NewRegistry()
	reg.MustRegister(c.rounds, c.failures, c.latency, c.lastSuccess)

	// Initialise both label values so the series exist from the first scrape.
	// Without this, "no failures yet" and "not running" look identical in a query.
	c.rounds.WithLabelValues("pass").Add(0)
	c.rounds.WithLabelValues("fail").Add(0)

	return reg, c
}

func (c *collectors) observe(res Result) {
	if res.Pass {
		c.rounds.WithLabelValues("pass").Inc()
		c.latency.Observe(res.Latency.Seconds())
		c.lastSuccess.Set(float64(time.Now().Unix()))
		return
	}
	c.rounds.WithLabelValues("fail").Inc()
	c.failures.WithLabelValues(res.Stage).Inc()
}

// serveMetrics exposes /metrics on the given port for a vmagent to scrape, and
// returns a function that shuts the server down.
//
// Port 0 disables the endpoint: the monitor still logs every round, it just
// publishes nothing. That is the right setting for a first run, before you have
// decided what the series should look like.
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

	// Give ListenAndServe a moment to fail on a bound port, so a misconfiguration
	// surfaces at startup rather than as a silently missing scrape target.
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