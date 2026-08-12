package metrics

import "github.com/prometheus/client_golang/prometheus"

var TotalSuccessfulIdentityRegistration = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "total_successful_identities_registration",
		Help:      "counter of successful identity registration",
	},
)

var TotalDecryptionKeysReceived = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "total_decryption_keys_received",
		Help:      "counter of total dec keys received",
	},
)

var TotalFailedRPCCalls = prometheus.NewCounter(
	prometheus.CounterOpts{
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
