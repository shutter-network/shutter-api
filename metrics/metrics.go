package metrics

import "github.com/prometheus/client_golang/prometheus"

var IdentityRegistrationsSubmitted = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "identity_registrations_submitted_total",
		Help:      "Count of identity registration transactions submitted to the RPC node.",
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
	prometheus.MustRegister(IdentityRegistrationsSubmitted)
	prometheus.MustRegister(DecryptionKeysReceived)
	prometheus.MustRegister(FailedRPCCalls)
	initBalanceMetrics()
}
