// Package txmgr serializes transaction submission for a single signer account.
//
// Every registration is signed by the same key, so all of them compete for one
// nonce sequence. Left to the generated bindings, a nil TransactOpts.Nonce makes
// each call resolve its own nonce, so two concurrent requests sign two
// transactions with the same one and only one of them can be mined.
//
// The Manager closes that window structurally rather than with locks: Send only
// queues a request, and a single goroutine owns nonce assignment, submission and
// everything in flight. That goroutine also polls for receipts, so this package
// holds no mutexes.
//
// A request is watched until it is mined, and if something else mines its nonce
// first it is carried over to a free one rather than failed. A transaction that
// goes RebroadcastAfter without being mined is sent again, priced to outbid the
// version it replaces, which doubles as gas bumping. Recomputing from the node's
// suggestion alone would not do: geth demands a bump on the tip as well as the
// fee cap, and the tip oracle does not move when the base fee does, so a
// transaction stranded below a risen base fee could never be replaced.
// MaxFeeCapPercent bounds how far that escalation goes.
//
// # Known limits
//
// Pending state is in memory and lost on restart. An account with no gas money
// is watched indefinitely and wedges registration, which shows up in
// pending_transactions and signer_balance_ether and clears once it is refilled.
// A transaction sent from this key by anything other than this process will
// collide with ours. Carrying a request over abandons a transaction that cannot
// be proven dead, so if the old one is still included the request lands twice:
// the time registry reverts the second with AlreadyRegistered, the event
// registry has no such error and registers the identity twice.
package txmgr

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/shutter-api/metrics"
)

const (
	// basefeeWiggleMultiplier mirrors the constant of the same name in
	// accounts/abi/bind/v2/base.go, so that owning gas pricing here changes who
	// calculates it without changing what gets paid.
	basefeeWiggleMultiplier = 2

	// priceBumpPercent is what geth's pool demands of a replacement, from
	// core/txpool/legacypool.DefaultConfig.PriceBump. Both the tip and the fee
	// cap must clear it, and both must be strictly greater than the incumbent's
	// (core/txpool/legacypool/list.go, list.Add).
	priceBumpPercent = 110
)

// Client is the subset of ethclient.Client the Manager needs.
type Client interface {
	NonceAt(ctx context.Context, account ecommon.Address, blockNumber *big.Int) (uint64, error)
	TransactionReceipt(ctx context.Context, txHash ecommon.Hash) (*types.Receipt, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// SubmitFunc signs and sends one contract call, which is what a generated
// binding method does. The Manager supplies opts with From, Signer, Nonce and
// both fee caps already set, so the closure only binds the call's own arguments
// and stays independent of any particular contract.
//
// It is invoked again for every resubmission, so it must be safe to call
// repeatedly. Note that it sends a transaction; it is not an eth_call.
type SubmitFunc func(opts *bind.TransactOpts) (*types.Transaction, error)

// The Manager's own reasons for ending a request. Any other error on an Err
// event comes from the node or from reading the chain.
//
// They are distinguished because they mean different things to a caller deciding
// what to tell its own client: the first two are proof that nothing was signed,
// while the third is not.
var (
	// ErrQueueFull means the worker is not keeping up and the request was turned
	// away without being signed.
	ErrQueueFull = errors.New("transaction queue is full")
	// ErrShutdown means the Manager stopped while the request was still queued.
	// Nothing was signed, so nothing can land.
	ErrShutdown = errors.New("transaction manager stopped before submitting")
	// ErrAbandoned means the Manager stopped while watching a transaction it had
	// already sent. That transaction is in the pool and may still be mined, so
	// the request cannot be reported as having failed, only as unknown.
	ErrAbandoned = errors.New("transaction abandoned while awaiting a receipt")
)

// Event is one thing that happened to a send request. Exactly one field is set.
//
// A caller that only needs something to report can take the first event and walk
// away. A caller that needs the outcome reads to the end, since Receipt and Err
// are terminal: one of them is always the last event, and the channel is closed
// after it.
type Event struct {
	// Tx is the transaction being watched on the request's behalf from now on. It
	// arrives once for the first submission and again for every resubmission that
	// replaces it, so the newest is the one to poll for and the earlier ones are
	// history rather than mistakes: a replacement should evict its predecessor,
	// but propagation is not atomic and any version may still be the one mined.
	Tx *types.Transaction
	// Receipt is the receipt of whichever version was mined. Whether the call
	// itself succeeded is in Receipt.Status: that is the contract's verdict rather
	// than the Manager's, and a caller holding the receipt can read it. TxHash
	// names the version that won, which need not be the last one announced.
	Receipt *types.Receipt
	// Err is the reason the Manager stopped working on the request. Every error
	// but ErrAbandoned means no transaction of ours can be mined; that one means
	// the Manager stopped looking rather than that anything failed.
	Err error
}

// eventBufferSize is how many events a request may hold for a caller that has
// stopped reading. Generous because a request produces one event per
// resubmission and those arrive for as long as it goes unmined, and cheap
// because the buffer only ever holds what a caller has not taken yet.
const eventBufferSize = 64

// Config tunes the Manager.
type Config struct {
	// PollInterval is how often pending transactions are checked for a receipt.
	PollInterval time.Duration
	// RebroadcastAfter is how long a transaction may go without a submission
	// attempt before it is sent again. It is an age per transaction, not a
	// period: a freshly submitted transaction is never resubmitted just because
	// an older one was due, which would replace a healthy transaction with a
	// more expensive one for no reason.
	RebroadcastAfter time.Duration
	// QueueSize bounds how many requests may wait for submission. Reaching it
	// means the worker is not keeping up, which is worth reporting rather than
	// absorbing.
	QueueSize int
	// MaxFeeCapPercent bounds what a resubmission may pay, as a percentage of
	// the fee cap the node currently suggests. 200 means never more than twice
	// the going rate. Capping the fee cap is enough to bound the spend, because
	// it also bounds the tip actually paid.
	//
	// A resubmission that cannot outbid the incumbent within it is skipped, and
	// the transaction waits for fees to fall. Without a ceiling the escalation
	// below would compound without limit.
	MaxFeeCapPercent uint64
}

// DefaultConfig polls once per block at Gnosis' five second block time.
func DefaultConfig() Config {
	return Config{
		PollInterval:     5 * time.Second,
		RebroadcastAfter: time.Minute,
		QueueSize:        1024,
		MaxFeeCapPercent: 200,
	}
}

// sendRequest represents a caller's request to send a transaction. It stores a
// channel to report what happens to it.
type sendRequest struct {
	submit SubmitFunc
	events chan Event
}

// publish announces an intermediate event, and drops it if the caller has left
// the buffer full. Dropping rather than blocking because this runs on the worker,
// and one caller that stopped reading must not be able to stall nonce assignment
// for every other request.
//
// The last slot is reserved so that finish always has room, which is what makes
// the terminal event the one thing a caller cannot miss.
func (r sendRequest) publish(ev Event) {
	if len(r.events) >= cap(r.events)-1 {
		log.Warn().Int("buffer", cap(r.events)).
			Msg("dropping transaction event, caller is not reading its channel")
		return
	}
	r.events <- ev
}

// finish announces the terminal event and closes the channel. The send cannot
// block: publish never occupies the last slot, and this is the last event, so
// nothing follows it into the buffer.
func (r sendRequest) finish(ev Event) {
	r.events <- ev
	close(r.events)
}

// pendingTransaction is a submitted request awaiting the chain's verdict. It
// outlives any single transaction, because a resubmission replaces the
// transaction while the request stays the same.
type pendingTransaction struct {
	sendRequest
	// txs is every version submitted for this request, oldest first. A
	// replacement should evict its predecessor, but propagation is not atomic
	// across nodes, so an earlier version can still be the one that gets mined.
	// All of them are watched, otherwise that would look like a stranger taking
	// our nonce and the request would be carried over and land twice.
	txs []*types.Transaction
	// lastAttempt is when the transaction was last sent, successfully or not.
	// Failed attempts count, otherwise a rejected resubmission would be retried
	// on every poll instead of once per RebroadcastAfter.
	lastAttempt time.Time
}

// tx is the version submitted most recently, and the one whose nonce counts.
func (p *pendingTransaction) tx() *types.Transaction {
	return p.txs[len(p.txs)-1]
}

func (p *pendingTransaction) nonce() uint64 {
	return p.tx().Nonce()
}

// Manager assigns nonces for one account and watches what it submits.
type Manager struct {
	client   Client
	from     ecommon.Address
	signer   bind.SignerFn
	cfg      Config
	requests chan sendRequest

	// Owned exclusively by the goroutine Start launches. Not guarded, because
	// nothing else touches it.
	//
	// A queue in nonce order rather than a map, because only the first can be
	// mined next and that is the only entry ever acted on. It stays ordered by
	// construction: new sends take the next nonce, and a carried-over request
	// takes one above the last.
	pending []*pendingTransaction
}

// NewManager builds a Manager for the given signing key. The chain ID is read
// once here rather than per request.
func NewManager(client Client, signingKey *ecdsa.PrivateKey, chainID *big.Int, cfg Config) (*Manager, error) {
	signer, err := bind.NewKeyedTransactorWithChainID(signingKey, chainID)
	if err != nil {
		return nil, err
	}
	defaults := DefaultConfig()
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if cfg.RebroadcastAfter <= 0 {
		cfg.RebroadcastAfter = defaults.RebroadcastAfter
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaults.QueueSize
	}
	if cfg.MaxFeeCapPercent <= 100 {
		cfg.MaxFeeCapPercent = defaults.MaxFeeCapPercent
	}
	return &Manager{
		client:   client,
		from:     signer.From,
		signer:   signer.Signer,
		cfg:      cfg,
		requests: make(chan sendRequest, cfg.QueueSize),
	}, nil
}

// From is the address every transaction is sent from. Identities are derived
// from it, so callers need it even when they are not sending.
func (m *Manager) From() ecommon.Address {
	return m.from
}

// Send queues a call and returns immediately, without making any RPC calls.
// Nothing has been sent yet when it returns, so neither a transaction hash nor a
// submission error exists until the first Event arrives.
//
// The returned channel reports every transaction sent for the request and ends
// with either a receipt or an error, whatever happens, so a caller waiting for
// the outcome is never left waiting forever. It is buffered, so a caller that
// takes what it needs and stops reading costs nothing; events beyond the buffer
// are dropped rather than delaying the worker, except the terminal one, which is
// always kept.
func (m *Manager) Send(submit SubmitFunc) <-chan Event {
	req := sendRequest{submit: submit, events: make(chan Event, eventBufferSize)}

	select {
	case m.requests <- req:
	default:
		m.reject(req, fmt.Errorf("%w (size %d)", ErrQueueFull, m.cfg.QueueSize))
	}
	return req.events
}

// Start runs the Manager until ctx is cancelled. It satisfies the
// rolling-shutter service interface.
//
// Submission and polling share one goroutine deliberately: that is what makes
// nonce assignment safe without locking, and a submission delaying a receipt
// check by a few hundred milliseconds costs nothing, since polling is only
// observation.
func (m *Manager) Start(ctx context.Context, runner service.Runner) error {
	runner.Go(func() error {
		ticker := time.NewTicker(m.cfg.PollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				m.shutdown()
				return ctx.Err()
			case req := <-m.requests:
				m.submit(ctx, req)
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	})
	return nil
}

// submit assigns a nonce, sends one queued request and starts watching it.
func (m *Manager) submit(ctx context.Context, req sendRequest) {
	nonce, err := m.assignNonce(ctx)
	if err != nil {
		m.reject(req, fmt.Errorf("failed to determine the next nonce: %w", err))
		return
	}

	tip, feeCap, err := m.gasPrices(ctx)
	if err != nil {
		m.reject(req, fmt.Errorf("failed to calculate gas prices: %w", err))
		return
	}

	tx, err := req.submit(m.transactOpts(ctx, nonce, tip, feeCap))
	if err != nil {
		// Nothing is tracked, so the nonce this request was given goes to the
		// next one instead of leaving a hole that later transactions would queue
		// behind forever. Safe without any interlock because this goroutine is
		// the only one that assigns nonces.
		m.reject(req, fmt.Errorf("failed to submit transaction: %w", err))
		return
	}

	m.pending = append(m.pending, &pendingTransaction{
		sendRequest: req,
		txs:         []*types.Transaction{tx},
		lastAttempt: time.Now(),
	})
	req.publish(Event{Tx: tx})

	metrics.PendingTransactions.Set(float64(len(m.pending)))
	log.Info().Str("tx_hash", tx.Hash().Hex()).Uint64("nonce", nonce).
		Msg("transaction submitted")
}

// assignNonce returns the nonce for the next submission: one above the last
// queued transaction, or the account's mined nonce when nothing is in flight.
//
// NonceAt rather than PendingNonceAt on purpose. After a restart our own
// transactions may still sit in the pool with nothing left to resubmit them, and
// deferring to them would queue everything new behind a blocker that no longer
// has anyone escalating it. Taking the mined frontier adopts that nonce and
// drives it forward instead.
func (m *Manager) assignNonce(ctx context.Context) (uint64, error) {
	if len(m.pending) > 0 {
		return m.lastPendingTransaction().nonce() + 1, nil
	}

	nonce, err := m.client.NonceAt(ctx, m.from, nil)
	if err != nil {
		metrics.FailedRPCCalls.Inc()
		return 0, err
	}
	return nonce, nil
}

// gasPrices reproduces what the bindings compute when the fee fields are left
// nil: the suggested tip, and a cap covering a doubling of the base fee.
func (m *Manager) gasPrices(ctx context.Context) (tip, feeCap *big.Int, err error) {
	tip, err = m.client.SuggestGasTipCap(ctx)
	if err != nil {
		metrics.FailedRPCCalls.Inc()
		return nil, nil, err
	}
	head, err := m.client.HeaderByNumber(ctx, nil)
	if err != nil {
		metrics.FailedRPCCalls.Inc()
		return nil, nil, err
	}
	if head.BaseFee == nil {
		return nil, nil, errors.New("chain is not EIP-1559 ready: header has no base fee")
	}
	feeCap = new(big.Int).Add(
		tip,
		new(big.Int).Mul(head.BaseFee, big.NewInt(basefeeWiggleMultiplier)),
	)
	return tip, feeCap, nil
}

// replacementPrices raises the suggested prices until the pool will accept the
// new transaction in place of the incumbent, and reports whether that stays
// within the ceiling.
//
// Recomputing from the node's suggestion is not enough on its own. The pool
// demands a bump on the tip as well as the fee cap, and SuggestGasTipCap is a
// tip oracle that does not move when the base fee does. So on a chain with
// steady tips every resubmission would be rejected as underpriced, and a
// transaction left below a risen base fee could never be replaced, wedging the
// whole queue behind it.
func replacementPrices(suggestedTip, suggestedFeeCap *big.Int, old *types.Transaction, maxFeeCapPercent uint64) (tip, feeCap *big.Int, ok bool) {
	tip = maxInt(suggestedTip, outbid(old.GasTipCap()))
	feeCap = maxInt(suggestedFeeCap, outbid(old.GasFeeCap()))

	ceiling := percentOf(suggestedFeeCap, maxFeeCapPercent)
	if feeCap.Cmp(ceiling) > 0 {
		return nil, nil, false
	}
	return tip, feeCap, true
}

// outbid is the least a field may be to displace an incumbent holding old: the
// percentage threshold, and at least one wei more, since the threshold rounds
// down and the pool also requires a strict increase.
func outbid(old *big.Int) *big.Int {
	return maxInt(percentOf(old, priceBumpPercent), new(big.Int).Add(old, big.NewInt(1)))
}

func percentOf(value *big.Int, percent uint64) *big.Int {
	scaled := new(big.Int).Mul(value, new(big.Int).SetUint64(percent))
	return scaled.Div(scaled, big.NewInt(100))
}

func maxInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) >= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

// transactOpts constructs opts with ctx, from address, signer, nonce, tip,
// and fee cap set. Gas limit is not set as the manager cannot compute it.
func (m *Manager) transactOpts(ctx context.Context, nonce uint64, tip, feeCap *big.Int) *bind.TransactOpts {
	return &bind.TransactOpts{
		From:      m.from,
		Signer:    m.signer,
		Nonce:     new(big.Int).SetUint64(nonce),
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Context:   ctx,
	}
}

// poll advances every pending transaction once: those the chain has decided are
// resolved, and the first in the queue is sent again if stale.
func (m *Manager) poll(ctx context.Context) {
	m.checkReceipts(ctx)
	m.resubmitFirstPending(ctx)
}

func (m *Manager) firstPendingTransaction() *pendingTransaction {
	return m.pending[0]
}

func (m *Manager) lastPendingTransaction() *pendingTransaction {
	return m.pending[len(m.pending)-1]
}

// remove drops a transaction from the queue, keeping the rest in nonce order.
func (m *Manager) remove(p *pendingTransaction) {
	for i, candidate := range m.pending {
		if candidate == p {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			return
		}
	}
}

// checkReceipts resolves every pending transaction the chain has decided on.
func (m *Manager) checkReceipts(ctx context.Context) {
	for _, p := range slices.Clone(m.pending) {
		for _, tx := range p.txs {
			receipt, err := m.client.TransactionReceipt(ctx, tx.Hash())
			if err == nil {
				m.resolve(p, Event{Receipt: receipt})
				break
			}

			// A missing receipt is the normal case for a transaction that has
			// not been mined yet. Any other error is a problem with the node,
			// worth reporting but not evidence about the transaction.
			if !errors.Is(err, ethereum.NotFound) {
				metrics.FailedRPCCalls.Inc()
				log.Err(err).Str("tx_hash", tx.Hash().Hex()).
					Msg("failed to query transaction receipt")
			}
		}
	}
}

// resubmitHead sends the lowest-nonce pending transaction again, if it has gone
// RebroadcastAfter without a submission attempt.
//
// Only that one, and only one per poll. Transactions are mined in nonce order,
// so the lowest is the only one the chain can accept next, and repricing the
// others cannot make them move until it does. Once it is mined or carried over
// the next takes its place and gets its turn, so nothing is starved. Prices are
// therefore always read immediately before the submission that uses them.
func (m *Manager) resubmitFirstPending(ctx context.Context) {
	if len(m.pending) == 0 {
		return
	}
	first := m.firstPendingTransaction()
	if time.Since(first.lastAttempt) < m.cfg.RebroadcastAfter {
		return
	}

	nonce := first.nonce()
	if accountNonce, err := m.client.NonceAt(ctx, m.from, nil); err != nil {
		// Without the mined nonce there is no telling whether this transaction
		// still holds a live one, so resubmit it as it is and look again next poll.
		metrics.FailedRPCCalls.Inc()
		log.Err(err).Msg("failed to read the account nonce")
	} else if nonce < accountNonce {
		// Something mined this nonce, and a whole RebroadcastAfter of receipt
		// checks has not turned up a receipt of ours, so it was not us. Carry
		// the request over to a free nonce.
		//
		// The transaction abandoned here is all but certainly dead, having lost
		// its nonce to a mined one, but that cannot be proven: if it is somehow
		// still included the request lands twice. On the time registry the
		// second one reverts with AlreadyRegistered; on the event registry both
		// succeed and the identity is registered twice.
		nonce = m.nextFreeNonce(accountNonce)
	}

	suggestedTip, suggestedFeeCap, err := m.gasPrices(ctx)
	if err != nil {
		log.Err(err).Msg("failed to calculate gas prices, skipping resubmission")
		return
	}

	// Only a resubmission at the same nonce has an incumbent to outbid. A
	// carried-over one takes a free nonce, so the suggestion stands.
	tip, feeCap := suggestedTip, suggestedFeeCap
	if nonce == first.nonce() {
		var withinCeiling bool
		tip, feeCap, withinCeiling = replacementPrices(
			suggestedTip, suggestedFeeCap, first.tx(), m.cfg.MaxFeeCapPercent)
		if !withinCeiling {
			// Outbidding would cost more than the ceiling allows, so wait for
			// fees to fall. lastAttempt still moves, otherwise this would be
			// recomputed on every poll rather than once per interval.
			first.lastAttempt = time.Now()
			log.Warn().Str("tx_hash", first.tx().Hash().Hex()).Uint64("nonce", nonce).
				Uint64("max_fee_cap_percent", m.cfg.MaxFeeCapPercent).
				Msg("cannot outbid own pending transaction within the fee ceiling")
			return
		}
	}

	first.lastAttempt = time.Now()
	tx, err := first.submit(m.transactOpts(ctx, nonce, tip, feeCap))
	switch {
	case err == nil:
		m.replaceTx(first, tx)
	case isBenignResubmitError(err):
		// Nothing to do, and nothing to record: the next poll reads the account
		// nonce and the receipt again, which is all these outcomes would have
		// told us.
		log.Debug().Err(err).Str("tx_hash", first.tx().Hash().Hex()).Uint64("nonce", nonce).
			Msg("resubmission was a no-op")
	default:
		metrics.FailedRPCCalls.Inc()
		log.Err(err).Str("tx_hash", first.tx().Hash().Hex()).Uint64("nonce", nonce).
			Msg("failed to resubmit transaction")
	}
}

// nextFreeNonce returns a nonce that no pending transaction occupies and that the
// chain has not already mined, so a carried-over request lands above the queue
// rather than colliding with a transaction of ours that is still live.
func (m *Manager) nextFreeNonce(accountNonce uint64) uint64 {
	if afterTail := m.lastPendingTransaction().nonce() + 1; afterTail > accountNonce {
		return afterTail
	}
	return accountNonce
}

// replaceTx records the transaction a successful resubmission produced, rekeying
// it if the request was carried over to a new nonce.
func (m *Manager) replaceTx(p *pendingTransaction, tx *types.Transaction) {
	old := p.tx()
	if tx.Hash() == old.Hash() {
		return
	}
	p.txs = append(p.txs, tx)
	p.publish(Event{Tx: tx})

	event := log.Info().Str("old_tx_hash", old.Hash().Hex()).Str("tx_hash", tx.Hash().Hex())
	if tx.Nonce() == old.Nonce() {
		event.Uint64("nonce", tx.Nonce()).Msg("resubmission replaced transaction at a higher price")
		return
	}

	// The new nonce is above every other in the queue, so the request belongs at
	// the end. Moving it keeps the queue ordered without sorting, and means a
	// carried-over request can never displace one that is still live.
	m.remove(p)
	m.pending = append(m.pending, p)

	event.Uint64("old_nonce", old.Nonce()).Uint64("nonce", tx.Nonce()).
		Msg("carried request over to a new nonce after losing the old one")
}

// resolve reports the chain's verdict and stops watching.
func (m *Manager) resolve(p *pendingTransaction, ev Event) {
	m.remove(p)

	label := statusLabel(ev)
	metrics.PendingTransactions.Set(float64(len(m.pending)))
	metrics.TransactionsResolved.WithLabelValues(label).Inc()

	// The mined version need not be the last one announced, so the receipt names
	// the transaction this is about whenever there is one.
	hash := p.tx().Hash()
	if ev.Receipt != nil {
		hash = ev.Receipt.TxHash
	}

	event := log.Info()
	if label != metrics.TxStatusConfirmed {
		event = log.Error()
	}
	event.Str("tx_hash", hash.Hex()).
		Uint64("nonce", p.nonce()).
		Str("status", label).
		Msg("transaction resolved")

	p.finish(ev)
}

// statusLabel is the metric label for a terminal event. It is finer grained than
// the events themselves on purpose: a revert is the contract's verdict rather
// than the Manager's, so callers read it off the receipt, but a revert rate is
// still worth alerting on.
func statusLabel(ev Event) string {
	switch {
	case ev.Receipt == nil:
		if errors.Is(ev.Err, ErrAbandoned) {
			return metrics.TxStatusAbandoned
		}
		return metrics.TxStatusRejected
	case ev.Receipt.Status == types.ReceiptStatusFailed:
		return metrics.TxStatusReverted
	default:
		return metrics.TxStatusConfirmed
	}
}

// reject ends a request that never made it onto the chain. It was never tracked,
// so there is nothing to stop watching. The counterpart to resolve: between them
// every request ends in exactly one place, counted and logged once.
func (m *Manager) reject(req sendRequest, err error) {
	ev := Event{Err: err}
	metrics.TransactionsResolved.WithLabelValues(statusLabel(ev)).Inc()
	log.Err(err).Msg("request rejected before submission")
	req.finish(ev)
}

// shutdown ends everything outstanding, so the guarantee of a terminal event
// followed by a close holds even for a Manager that is going away and no caller
// waits on a channel that will never fire.
func (m *Manager) shutdown() {
	for _, p := range slices.Clone(m.pending) {
		m.resolve(p, Event{Err: ErrAbandoned})
	}
	for {
		select {
		case req := <-m.requests:
			m.reject(req, ErrShutdown)
		default:
			return
		}
	}
}

// isBenignResubmitError reports whether a failed resubmission needs no action.
//
// "already known" is routine: the pool has the transaction and the resubmission
// changed nothing about it. "replacement transaction underpriced" means the
// outbid was not enough, which should be rare now that resubmissions price
// against the incumbent, but can still happen if the node saw a higher version
// than the one we hold.
//
// "nonce too low" is different: the nonce is read immediately before
// submitting, so it only appears when the nonce is mined in the moment between
// the two calls. It is ignored rather than expected. Reporting it as a failure
// would be wrong, since nothing failed on our side and the next poll reads the
// nonce again and carries the request over, and the only cost of the race is
// that the carry-over waits one more RebroadcastAfter.
//
// These are geth's error strings, from core/txpool.ErrAlreadyKnown,
// core/txpool.ErrReplaceUnderpriced and core.ErrNonceTooLow. They arrive over
// RPC as plain text rather than typed errors, so they cannot be compared with
// errors.Is, and a non-geth node may word them differently.
func isBenignResubmitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, expected := range []string{
		"already known",
		"replacement transaction underpriced",
		"nonce too low",
	} {
		if strings.Contains(msg, expected) {
			return true
		}
	}
	return false
}
