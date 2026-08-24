package usecase

import (
	"context"
	"errors"
	"net/http"
	"time"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	httpError "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/internal/txmgr"
	"github.com/shutter-network/shutter-api/metrics"
)

// TxManagerInterface is the part of txmgr.Manager the registration endpoints use.
type TxManagerInterface interface {
	// From is the address registrations are sent from, and the one identities are
	// derived from.
	From() ecommon.Address
	// Send queues a call and returns without sending it. Nothing has reached the
	// node when it returns, so the transaction hash arrives on the channel rather
	// than from the call.
	Send(submit txmgr.SubmitFunc) <-chan txmgr.Event
}

// submitTimeout bounds how long a registration waits for its transaction to reach
// the node. It has to cover assigning a nonce, reading gas prices and
// broadcasting, so a handful of RPC round trips, plus the wait behind any
// submissions already queued in front of it, since one goroutine performs them in
// sequence. It does not cover waiting for a block, because the response carries a
// transaction hash rather than a receipt.
//
// Generous rather than tight, because giving up does not cancel anything. The
// transaction is still sent, so a client told its registration failed may find it
// on chain regardless, and waiting a little longer costs far less than that does.
const submitTimeout = 5 * time.Second

// awaitSubmission waits for the transaction a registration produced and returns
// its hash, or the error to answer the request with.
//
// The reason never reaches the client, only the log: it describes our node and our
// queue, which is nothing a client can act on. A full queue is the exception,
// because "overloaded, come back later" is something it can.
//
// Later events are left on the channel for whoever wants them, including the one
// that says how the transaction ended.
func awaitSubmission(ctx context.Context, events <-chan txmgr.Event) (ecommon.Hash, *httpError.Http) {
	ctx, cancel := context.WithTimeout(ctx, submitTimeout)
	defer cancel()

	select {
	case ev, open := <-events:
		switch {
		case !open:
			// The manager reports an outcome before closing, always, so this is a
			// bug in it rather than a state to handle.
			log.Error().Msg("transaction manager closed a request without reporting anything")
		case ev.Tx != nil:
			return ev.Tx.Hash(), nil
		case ev.Receipt != nil:
			// Already mined, which is unlikely this early but not a problem: the
			// receipt names the transaction just as well as the transaction does.
			return ev.Receipt.TxHash, nil
		case errors.Is(ev.Err, txmgr.ErrQueueFull):
			log.Err(ev.Err).Msg("rejecting registration, too many are already in flight")
			err := httpError.NewHttpError(
				"too many registrations in flight, please retry",
				"",
				http.StatusServiceUnavailable,
			)
			return ecommon.Hash{}, &err
		default:
			log.Err(ev.Err).Msg("failed to submit registration")
		}
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// The request is still queued and will be submitted, so the
			// registration may land after this answer says it did not. Counted
			// because that is a discrepancy worth reconciling rather than a
			// failure worth ignoring.
			metrics.SubmissionTimeouts.Inc()
			log.Error().Dur("timeout", submitTimeout).
				Msg("gave up waiting for a registration to be submitted, it may still be sent")
		} else {
			log.Debug().Msg("caller went away before the registration was submitted")
		}
	}

	err := httpError.NewHttpError(
		"failed to register identity",
		"",
		http.StatusInternalServerError,
	)
	return ecommon.Hash{}, &err
}
