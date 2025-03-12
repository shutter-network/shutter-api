package metrics

import "github.com/prometheus/client_golang/prometheus"

var TotalSuccessfulIdentityRegistration = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "shutter_api",
		Name:      "total_successful_identities_registration",
		Help:      "counter of successful identity registration",
	},
)

var TotalDecryptionKeysReceived = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "shutter_api",
		Name:      "total_decryption_keys_received",
		Help:      "counter of total dec keys received",
	},
)

var TotalFailedRPCCalls = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "shutter_api",
		Name:      "total_failed_rpc_calls",
		Help:      "Counter of failed rpc calls",
	},
)

func InitMetrics() {
	prometheus.MustRegister(TotalSuccessfulIdentityRegistration)
	prometheus.MustRegister(TotalDecryptionKeysReceived)
	prometheus.MustRegister(TotalFailedRPCCalls)
}
