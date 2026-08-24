package metrics

import "github.com/prometheus/client_golang/prometheus"

var SuccessfulIdentityRegistrations = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "successful_identity_registrations_total",
		Help:      "Count of successful identity registrations.",
	},
)

var DecryptionKeysReceived = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "decryption_keys_received_total",
		Help:      "Count of decryption keys received from the keypers.",
	},
)

var FailedRPCCalls = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "failed_rpc_calls_total",
		Help:      "Count of failed RPC calls.",
	},
)

func InitMetrics() {
	prometheus.MustRegister(SuccessfulIdentityRegistrations)
	prometheus.MustRegister(DecryptionKeysReceived)
	prometheus.MustRegister(FailedRPCCalls)
	initBalanceMetrics()
	initTransactionMetrics()
}
