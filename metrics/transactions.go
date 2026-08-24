package metrics

import "github.com/prometheus/client_golang/prometheus"

// Terminal states a send request can reach, used as the status label on
// TransactionsResolved. Exported so the transaction manager and the tests agree
// on the spelling.
//
// These are finer grained than what the transaction manager reports to its
// callers, which is a receipt or an error. A revert is the contract's verdict
// rather than the manager's, so callers read it off the receipt, but a revert
// rate is still worth alerting on. Rejected and abandoned are one error to a
// caller that only wants to know it will not be mined, and two series here.
const (
	TxStatusConfirmed = "confirmed"
	TxStatusReverted  = "reverted"
	TxStatusAbandoned = "abandoned"
	TxStatusRejected  = "rejected"
)

// txStatuses is every value TransactionsResolved is ever incremented with.
var txStatuses = []string{
	TxStatusConfirmed,
	TxStatusReverted,
	TxStatusAbandoned,
	TxStatusRejected,
}

// TransactionsResolved counts send requests by the state they finished in.
// SuccessfulIdentityRegistrations counts submissions, which says nothing about
// whether a transaction was mined; this is the counter that does.
var TransactionsResolved = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "transactions_resolved_total",
		Help:      "Count of send requests by terminal state.",
	},
	[]string{"status"},
)

// SubmissionTimeouts counts requests answered with an error while their
// transaction was still on its way to the node. Giving up waiting does not stop
// the transaction, so each one of these is a client told its registration failed
// that may have landed on chain anyway, and a candidate for reconciliation.
var SubmissionTimeouts = prometheus.NewCounter(
	prometheus.CounterOpts{
		Namespace: "shutter_api",
		Name:      "submission_timeouts_total",
		Help:      "Count of requests that gave up waiting for their transaction to be submitted.",
	},
)

// PendingTransactions is the number of submitted transactions still waiting for
// a receipt. The transaction manager never gives up on one, so a value that
// climbs and does not fall means registrations are being accepted but not
// mined, and every later registration is queued behind them.
var PendingTransactions = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: "shutter_api",
		Name:      "pending_transactions",
		Help:      "Number of submitted transactions still awaiting a receipt.",
	},
)

// initTransactionMetrics registers the transaction metrics and creates every
// status series up front, so a rate() over a state that has not happened yet
// reads as zero instead of returning no data.
func initTransactionMetrics() {
	prometheus.MustRegister(TransactionsResolved)
	prometheus.MustRegister(SubmissionTimeouts)
	prometheus.MustRegister(PendingTransactions)

	for _, status := range txStatuses {
		TransactionsResolved.WithLabelValues(status)
	}
}
