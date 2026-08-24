package txmgr

import (
	"context"
	"errors"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/shutter-api/metrics"
	"github.com/stretchr/testify/require"
)

// TestMain silences the manager's logging, which is per transaction per poll and
// would otherwise bury the test output.
func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// Fixed so failures reproduce. Any valid secp256k1 scalar will do.
const testSigningKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

var (
	testChainID = big.NewInt(100) // Gnosis
	testTo      = ecommon.HexToAddress("0x1111111111111111111111111111111111111111")
	testTip     = big.NewInt(1_000_000_000)
	testBaseFee = big.NewInt(7_000_000_000)
)

// fakeClient stands in for ethclient.Client. A fake is used rather than a
// simulated chain because the interesting cases here are node behaviours we
// cannot easily provoke for real: a nonce stolen by someone else, a receipt that
// has not propagated yet, a pool that forgot a transaction.
type fakeClient struct {
	mu sync.Mutex

	accountNonce uint64
	nonceAtCalls int
	nonceAtErr   error

	receipts   map[ecommon.Hash]*types.Receipt
	receiptErr error

	tip     *big.Int
	baseFee *big.Int
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		receipts: make(map[ecommon.Hash]*types.Receipt),
		tip:      new(big.Int).Set(testTip),
		baseFee:  new(big.Int).Set(testBaseFee),
	}
}

func (c *fakeClient) NonceAt(_ context.Context, _ ecommon.Address, _ *big.Int) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonceAtCalls++
	if c.nonceAtErr != nil {
		return 0, c.nonceAtErr
	}
	return c.accountNonce, nil
}

func (c *fakeClient) TransactionReceipt(_ context.Context, hash ecommon.Hash) (*types.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.receiptErr != nil {
		return nil, c.receiptErr
	}
	if receipt, ok := c.receipts[hash]; ok {
		return receipt, nil
	}
	return nil, ethereum.NotFound
}

func (c *fakeClient) SuggestGasTipCap(_ context.Context) (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return new(big.Int).Set(c.tip), nil
}

func (c *fakeClient) HeaderByNumber(_ context.Context, _ *big.Int) (*types.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &types.Header{BaseFee: new(big.Int).Set(c.baseFee)}, nil
}

func (c *fakeClient) setReceipt(hash ecommon.Hash, status uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receipts[hash] = &types.Receipt{Status: status, BlockNumber: big.NewInt(42), TxHash: hash}
}

func (c *fakeClient) setBaseFee(wei int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseFee = big.NewInt(wei)
}

func (c *fakeClient) setReceiptErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receiptErr = err
}

func (c *fakeClient) setAccountNonce(nonce uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accountNonce = nonce
}

func (c *fakeClient) chainReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonceAtCalls
}

// submitter is a SubmitFunc that records the opts it was handed and can be told
// to fail. It stands in for a generated contract binding.
type submitter struct {
	mu    sync.Mutex
	seen  []*bind.TransactOpts
	built []*types.Transaction
	err   error
}

func (s *submitter) submit(opts *bind.TransactOpts) (*types.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seen = append(s.seen, opts)
	if s.err != nil {
		return nil, s.err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   testChainID,
		Nonce:     opts.Nonce.Uint64(),
		GasTipCap: opts.GasTipCap,
		GasFeeCap: opts.GasFeeCap,
		Gas:       21000,
		To:        &testTo,
	})
	s.built = append(s.built, tx)
	return tx, nil
}

func (s *submitter) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// nonces is every nonce submission was attempted with, in order, so a test can
// tell which transactions a resubmission round touched.
func (s *submitter) nonces() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, 0, len(s.seen))
	for _, opts := range s.seen {
		out = append(out, opts.Nonce.Uint64())
	}
	return out
}

func (s *submitter) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// lastTx is how a test running against Start learns a hash, since the pending
// queue belongs to the worker goroutine and must not be read from outside it.
func (s *submitter) lastTx() *types.Transaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.built) == 0 {
		return nil
	}
	return s.built[len(s.built)-1]
}

func newTestManager(t *testing.T, client Client) *Manager {
	t.Helper()
	key, err := crypto.HexToECDSA(testSigningKey)
	require.NoError(t, err)
	m, err := NewManager(client, key, testChainID, DefaultConfig())
	require.NoError(t, err)
	return m
}

// drain submits every queued request. Production code does this in the Start
// loop; tests call it directly so they can drive the Manager one step at a time,
// on the same goroutine that owns its state.
func drain(m *Manager) {
	for {
		select {
		case req := <-m.requests:
			m.submit(context.Background(), req)
		default:
			return
		}
	}
}

// send queues a call and submits it, which is what Start would have done.
func send(m *Manager, submit SubmitFunc) <-chan Event {
	events := m.Send(submit)
	drain(m)
	return events
}

// lastEvent reads a request's events to the end and returns the last one, also
// checking the contract every request is meant to honour: the last event is
// terminal, and the channel is closed after it.
func lastEvent(t *testing.T, events <-chan Event) Event {
	t.Helper()
	var last Event
	for {
		select {
		case ev, open := <-events:
			if !open {
				require.True(t, last.Receipt != nil || last.Err != nil,
					"the last event before the channel closed must be a receipt or an error")
				return last
			}
			last = ev
		case <-time.After(2 * time.Second):
			t.Fatal("the request never ended")
		}
	}
}

// requireWatched requires that a request has not ended, consuming the
// transactions announced so far. Every event before the last is a transaction, so
// anything else here means the request resolved when it should not have.
func requireWatched(t *testing.T, events <-chan Event) {
	t.Helper()
	for {
		select {
		case ev, open := <-events:
			require.True(t, open, "the request ended when it should still be watched")
			require.Nil(t, ev.Receipt, "the request was resolved when it should still be watched")
			require.NoError(t, ev.Err, "the request was failed when it should still be watched")
			require.NotNil(t, ev.Tx, "an event set no field")
		default:
			return
		}
	}
}

// announcedTxs is every transaction a request has announced so far.
func announcedTxs(t *testing.T, events <-chan Event) []*types.Transaction {
	t.Helper()
	var out []*types.Transaction
	for {
		select {
		case ev, open := <-events:
			require.True(t, open, "the request ended")
			require.NotNil(t, ev.Tx, "expected a transaction event")
			out = append(out, ev.Tx)
		default:
			return out
		}
	}
}

// makeStale backdates a pending transaction so the next poll resubmits it.
func makeStale(t *testing.T, m *Manager, nonce uint64) {
	t.Helper()
	for _, p := range m.pending {
		if p.nonce() == nonce {
			p.lastAttempt = time.Now().Add(-2 * m.cfg.RebroadcastAfter)
			return
		}
	}
	t.Fatalf("no pending transaction with nonce %d", nonce)
}

// pendingWithNonce returns the queued transaction holding a given nonce.
func pendingWithNonce(t *testing.T, m *Manager, nonce uint64) *pendingTransaction {
	t.Helper()
	for _, p := range m.pending {
		if p.nonce() == nonce {
			return p
		}
	}
	t.Fatalf("no pending transaction with nonce %d", nonce)
	return nil
}

// pendingNonces returns the nonces currently in flight, in order.
func pendingNonces(m *Manager) []uint64 {
	out := make([]uint64, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p.nonce())
	}
	return out
}

// onlyPending returns the single pending transaction.
func onlyPending(t *testing.T, m *Manager) *pendingTransaction {
	t.Helper()
	require.Len(t, m.pending, 1)
	return m.pending[0]
}

// TestConcurrentSendsGetDistinctSequentialNonces is the regression test for the
// bug this package exists to fix. Against the old code, which left
// TransactOpts.Nonce nil and let every call resolve its own, this fails with the
// same nonce issued repeatedly.
func TestConcurrentSendsGetDistinctSequentialNonces(t *testing.T) {
	const senders = 50

	client := newFakeClient()
	client.accountNonce = 7
	m := newTestManager(t, client)
	s := &submitter{}

	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Send(s.submit)
		}()
	}
	wg.Wait()
	drain(m)

	seen := make(map[uint64]bool)
	for _, nonce := range s.nonces() {
		require.False(t, seen[nonce], "nonce %d issued twice", nonce)
		seen[nonce] = true
	}
	require.Len(t, seen, senders)
	for nonce := uint64(7); nonce < 7+senders; nonce++ {
		require.True(t, seen[nonce], "nonce %d missing from the sequence", nonce)
	}

	// Only the first submission finds nothing in flight, so the chain is read
	// once no matter how many registrations arrive together.
	require.Equal(t, 1, client.chainReads())
}

func TestSendDoesNotTouchTheNetwork(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := m.Send(s.submit)

	require.Zero(t, client.chainReads(), "Send must not make RPC calls")
	require.Zero(t, s.attempts(), "Send must not build a transaction")
	require.Empty(t, events, "Send must not report anything before the worker runs")

	drain(m)
	require.Equal(t, 1, s.attempts())
	require.Equal(t, s.lastTx().Hash(), (<-events).Tx.Hash(),
		"submitting must announce the transaction")
}

func TestChainIsReadOnlyWhenNothingIsInFlight(t *testing.T) {
	client := newFakeClient()
	client.accountNonce = 3
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)
	first := onlyPending(t, m)
	require.Equal(t, uint64(3), first.nonce())
	require.Equal(t, 1, client.chainReads())

	send(m, s.submit)
	require.Equal(t, 1, client.chainReads(), "chain read again while work was in flight")

	// Empty the set, and the next submission goes back to the chain.
	client.setReceipt(first.tx().Hash(), types.ReceiptStatusSuccessful)
	m.poll(context.Background())
	require.NotNil(t, lastEvent(t, events).Receipt)

	m.shutdown()
	send(m, s.submit)
	require.Equal(t, 2, client.chainReads())
}

func TestFailedSubmissionReusesTheNonce(t *testing.T) {
	client := newFakeClient()
	client.accountNonce = 11
	m := newTestManager(t, client)
	s := &submitter{}

	submitErr := errors.New("connection refused")
	s.fail(submitErr)
	events := send(m, s.submit)
	require.ErrorIs(t, lastEvent(t, events).Err, submitErr,
		"the caller should be told why submission failed")
	require.Empty(t, m.pending, "a failed submission must not be watched")

	s.fail(nil)
	send(m, s.submit)
	require.Equal(t, uint64(11), onlyPending(t, m).nonce(),
		"a failed submission must not consume its nonce")
}

func TestRequestIsRejectedWhenChainNonceUnavailable(t *testing.T) {
	client := newFakeClient()
	client.nonceAtErr = errors.New("rpc down")
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)

	require.ErrorIs(t, lastEvent(t, events).Err, client.nonceAtErr)
	require.Zero(t, s.attempts(), "no transaction should be built without a nonce")
}

func TestFullQueueRejectsImmediately(t *testing.T) {
	client := newFakeClient()
	key, err := crypto.HexToECDSA(testSigningKey)
	require.NoError(t, err)
	m, err := NewManager(client, key, testChainID, Config{QueueSize: 1})
	require.NoError(t, err)
	s := &submitter{}

	require.Empty(t, m.Send(s.submit), "the first request fits in the queue")

	// Nothing has drained the queue, so this one has nowhere to go.
	events := m.Send(s.submit)
	ev := lastEvent(t, events)
	require.ErrorIs(t, ev.Err, ErrQueueFull)
	require.Nil(t, ev.Tx, "a request that was never sent has no transaction")
}

func TestGasPricesFollowTheBindingFormula(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)

	s.mu.Lock()
	opts := s.seen[0]
	s.mu.Unlock()

	require.Equal(t, testTip, opts.GasTipCap)
	// tip + 2*basefee, matching basefeeWiggleMultiplier in the bindings.
	want := new(big.Int).Add(testTip, new(big.Int).Mul(testBaseFee, big.NewInt(2)))
	require.Equal(t, want, opts.GasFeeCap)
	require.Zero(t, opts.GasLimit, "the gas limit is the bindings' business to estimate, not ours")
	require.Equal(t, m.From(), opts.From)
	require.NotNil(t, opts.Signer)
}

// A revert is the contract's verdict, not the Manager's, so both outcomes
// resolve as confirmed and the caller reads Receipt.Status to tell them apart.
func TestPollResolvesAnyMinedTransactionAsConfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status uint64
	}{
		{"mined successfully", types.ReceiptStatusSuccessful},
		{"mined but reverted", types.ReceiptStatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeClient()
			m := newTestManager(t, client)
			s := &submitter{}

			events := send(m, s.submit)
			p := onlyPending(t, m)

			m.poll(context.Background())
			requireWatched(t, events)

			client.setReceipt(p.tx().Hash(), tc.status)
			m.poll(context.Background())

			ev := lastEvent(t, events)
			require.NotNil(t, ev.Receipt)
			require.Equal(t, tc.status, ev.Receipt.Status)
			require.NoError(t, ev.Err, "a mined transaction is not an error, whatever it did")
		})
	}
}

// Something else mining our nonce must retry the request at a free one rather
// than fail it.
func TestStaleTransactionWhoseNonceWasMinedIsCarriedOver(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)
	require.Equal(t, uint64(0), onlyPending(t, m).nonce())

	// Something else mined nonce 0, so ours never can be.
	client.setAccountNonce(1)
	makeStale(t, m, 0)
	m.poll(context.Background())

	requireWatched(t, events) // the request must be retried, not failed
	require.Equal(t, []uint64{0, 1}, s.nonces(), "the request should move to the free nonce")
	require.Equal(t, []uint64{1}, pendingNonces(m))

	// It is the same request, so the original caller still gets the answer.
	client.setReceipt(onlyPending(t, m).tx().Hash(), types.ReceiptStatusSuccessful)
	m.poll(context.Background())
	require.NotNil(t, lastEvent(t, events).Receipt)
}

// Staleness is the grace period: a transaction is only carried over once a whole
// RebroadcastAfter of receipt checks has come up empty. A fresh transaction whose
// nonce merely looks mined must be left alone, since the most likely explanation
// is that it was mined by us and the receipt has not propagated.
func TestFreshTransactionWhoseNonceWasMinedIsLeftAlone(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	client.setAccountNonce(1)

	m.poll(context.Background())

	require.Equal(t, []uint64{0}, s.nonces(), "a fresh transaction must not be carried over")
	require.Equal(t, []uint64{0}, pendingNonces(m))
}

// A rejected resubmission still counts as an attempt. Otherwise the transaction
// stays stale and is retried on every poll, turning a one minute interval into a
// five second one.
func TestRejectedResubmissionStillResetsTheClock(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	s.fail(errors.New("already known"))
	makeStale(t, m, onlyPending(t, m).nonce())

	m.poll(context.Background())
	require.Equal(t, 2, s.attempts(), "the stale transaction should be resubmitted once")

	m.poll(context.Background())
	require.Equal(t, 2, s.attempts(), "a failed attempt must still count as an attempt")
}

// A replacement is a new transaction for the same request, so it must not become
// a second queue entry or a second caller.
func TestAReplacementStaysTheSameRequest(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)
	p := onlyPending(t, m)
	original := p.tx()

	makeStale(t, m, p.nonce())
	m.poll(context.Background())

	require.Len(t, m.pending, 1, "the replacement must not become a second entry")
	require.Equal(t, original.Nonce(), p.nonce(), "a replacement keeps the nonce")
	require.NotEqual(t, original.Hash(), p.tx().Hash(), "the tracked transaction should have changed")

	// The caller's channel survives the swap and reports the winning version.
	client.setReceipt(p.tx().Hash(), types.ReceiptStatusSuccessful)
	m.poll(context.Background())
	require.Equal(t, p.tx().Hash(), lastEvent(t, events).Receipt.TxHash)
}

// A caller that wants to know what to watch has to be told every time that
// changes, otherwise it is left polling a hash the Manager has already given up
// on.
func TestEveryVersionSentIsAnnounced(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)
	for round := 0; round < 2; round++ {
		makeStale(t, m, 0)
		m.poll(context.Background())
	}
	require.Equal(t, 3, s.attempts(), "expected an original and two replacements")

	announced := announcedTxs(t, events)
	require.Len(t, announced, 3, "every version sent must be announced")

	s.mu.Lock()
	built := s.built
	s.mu.Unlock()
	for i, tx := range announced {
		require.Equal(t, built[i].Hash(), tx.Hash(), "version %d announced out of order", i)
	}

	// The last event is still the outcome, and it names the version that won.
	client.setReceipt(announced[2].Hash(), types.ReceiptStatusSuccessful)
	m.poll(context.Background())
	require.Equal(t, announced[2].Hash(), lastEvent(t, events).Receipt.TxHash)
}

// The buffer is finite and the worker must never wait on a caller, so an
// abandoned channel loses intermediate events. The outcome is not intermediate,
// and losing it would leave a caller that comes back later unable to tell what
// happened, so a slot is reserved for it.
func TestAFullChannelStillDeliversTheOutcome(t *testing.T) {
	req := sendRequest{events: make(chan Event, eventBufferSize)}

	for i := 0; i < eventBufferSize*2; i++ {
		req.publish(Event{Tx: types.NewTx(&types.DynamicFeeTx{Nonce: uint64(i)})})
	}
	req.finish(Event{Err: ErrAbandoned})

	require.Len(t, req.events, eventBufferSize, "the reserved slot should have been used by finish")

	var last Event
	for ev := range req.events {
		last = ev
	}
	require.ErrorIs(t, last.Err, ErrAbandoned, "the outcome must survive a full buffer")
}

// Transactions are mined in nonce order, so the lowest is the only one the chain
// can accept next. Repricing the ones behind it cannot make them move and would
// pay more gas for nothing.
func TestOnlyTheLowestNoncePendingTransactionIsResubmitted(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	send(m, s.submit)
	send(m, s.submit)
	for nonce := uint64(0); nonce < 3; nonce++ {
		makeStale(t, m, nonce)
	}

	m.poll(context.Background())
	require.Equal(t, []uint64{0, 1, 2, 0}, s.nonces())

	// Its turn is over until it goes stale again, and the ones behind it still
	// wait on it, so a second poll changes nothing.
	m.poll(context.Background())
	require.Equal(t, []uint64{0, 1, 2, 0}, s.nonces())
}

// Once the head is mined the next takes its place, so nothing behind it is
// starved by only ever resubmitting the head.
func TestTheNextTransactionTakesItsTurnOnceTheHeadIsMined(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	send(m, s.submit)
	makeStale(t, m, 0)
	makeStale(t, m, 1)

	m.poll(context.Background())
	require.Equal(t, []uint64{0, 1, 0}, s.nonces(), "only the head is resubmitted")

	client.setReceipt(pendingWithNonce(t, m, 0).tx().Hash(), types.ReceiptStatusSuccessful)
	client.setAccountNonce(1)
	m.poll(context.Background())

	require.Equal(t, []uint64{0, 1, 0, 1}, s.nonces(), "nonce 1 is the head now and was stale")
	require.Equal(t, []uint64{1}, pendingNonces(m))
}

func TestAFreshHeadIsNotResubmitted(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	send(m, s.submit)
	// Only the one behind the head is stale, and it cannot move until the head
	// does, so nothing should be sent.
	makeStale(t, m, 1)

	m.poll(context.Background())
	require.Equal(t, []uint64{0, 1}, s.nonces())
}

// The pool rejects a resubmission on every calm-chain poll, so those rejections
// must not read as RPC failures. Otherwise the failure metric climbs steadily
// while nothing is wrong, and a real problem is invisible in the noise. A nonce
// mined between reading it and submitting is rarer, but equally not our failure.
func TestBenignResubmitOutcomesAreNotCountedAsFailures(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)

	for _, expected := range []string{
		"already known",
		"replacement transaction underpriced",
		"nonce too low",
	} {
		s.fail(errors.New(expected))
		makeStale(t, m, 0)

		before := testutil.ToFloat64(metrics.FailedRPCCalls)
		m.poll(context.Background())

		require.Equal(t, before, testutil.ToFloat64(metrics.FailedRPCCalls),
			"%q must not count as an RPC failure", expected)
		requireWatched(t, events)
		require.Len(t, m.pending, 1, "%q must leave the request being watched", expected)
	}

	// Anything else does.
	s.fail(errors.New("intrinsic gas too low"))
	makeStale(t, m, 0)

	before := testutil.ToFloat64(metrics.FailedRPCCalls)
	m.poll(context.Background())
	require.Equal(t, before+1, testutil.ToFloat64(metrics.FailedRPCCalls))
}

// geth rejects a replacement unless BOTH the tip and the fee cap are strictly
// greater than the incumbent's and clear 110% (list.Add). SuggestGasTipCap is a
// tip oracle that does not move with the base fee, so pricing a resubmission
// from the suggestion alone would leave the tip flat and every replacement would
// be rejected, stranding a transaction under a risen base fee forever.
func TestResubmissionOutbidsTheIncumbentEvenWhenSuggestionsAreFlat(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)
	original := onlyPending(t, m).tx()

	// Suggestions unchanged, exactly as a calm-tip chain behaves.
	makeStale(t, m, 0)
	m.poll(context.Background())

	bumped := onlyPending(t, m).tx()
	require.Positive(t, bumped.GasTipCap().Cmp(original.GasTipCap()), "tip must rise")
	require.Positive(t, bumped.GasFeeCap().Cmp(original.GasFeeCap()), "fee cap must rise")
	requireClearsGethThreshold(t, original, bumped)
}

// requireClearsGethThreshold applies geth's own replacement rule, so the test
// fails if a bump would be rejected by the pool.
func requireClearsGethThreshold(t *testing.T, old, replacement *types.Transaction) {
	t.Helper()

	require.Positive(t, replacement.GasFeeCap().Cmp(old.GasFeeCap()), "fee cap must be strictly greater")
	require.Positive(t, replacement.GasTipCap().Cmp(old.GasTipCap()), "tip must be strictly greater")

	hundred := big.NewInt(100)
	bump := big.NewInt(priceBumpPercent)
	feeCapThreshold := new(big.Int).Div(new(big.Int).Mul(bump, old.GasFeeCap()), hundred)
	tipThreshold := new(big.Int).Div(new(big.Int).Mul(bump, old.GasTipCap()), hundred)

	require.GreaterOrEqual(t, replacement.GasFeeCap().Cmp(feeCapThreshold), 0, "fee cap below the 110% threshold")
	require.GreaterOrEqual(t, replacement.GasTipCap().Cmp(tipThreshold), 0, "tip below the 110% threshold")
}

// Escalation compounds, so without a ceiling a transaction that never mines
// would bid the account dry.
func TestResubmissionStopsAtTheFeeCeiling(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	send(m, s.submit)

	// Offer it the chance to escalate far more often than the ceiling allows at
	// 110% a round. It has to stop bidding of its own accord.
	stopped := false
	for round := 0; round < 50 && !stopped; round++ {
		before := s.attempts()
		makeStale(t, m, 0)
		m.poll(context.Background())
		stopped = s.attempts() == before
	}
	require.True(t, stopped, "escalation never stopped, the ceiling is not enforced")

	suggestedFeeCap := new(big.Int).Add(testTip, new(big.Int).Mul(testBaseFee, big.NewInt(2)))
	ceiling := new(big.Int).Div(
		new(big.Int).Mul(suggestedFeeCap, new(big.Int).SetUint64(m.cfg.MaxFeeCapPercent)),
		big.NewInt(100),
	)
	paid := onlyPending(t, m).tx().GasFeeCap()
	require.LessOrEqual(t, paid.Cmp(ceiling), 0, "paid %s, ceiling %s", paid, ceiling)

	// Still watched, so it resolves if fees fall and it is finally mined.
	require.Len(t, m.pending, 1)
}

// A replacement should evict its predecessor, but propagation is not atomic. If
// an earlier version is the one mined, that must read as our transaction
// succeeding, not as a stranger taking the nonce.
func TestAnEarlierVersionBeingMinedResolvesTheRequest(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)
	original := onlyPending(t, m).tx()

	makeStale(t, m, 0)
	m.poll(context.Background())
	bumped := onlyPending(t, m).tx()
	require.NotEqual(t, original.Hash(), bumped.Hash(), "the resubmission should have replaced it")

	// The version we stopped tracking is the one that lands.
	client.setReceipt(original.Hash(), types.ReceiptStatusSuccessful)
	client.setAccountNonce(1)
	m.poll(context.Background())

	// Checked before reading the channel so that failing to notice the earlier
	// version reports itself here, rather than blocking on an outcome that a
	// manager watching only the newest version would never deliver.
	require.Empty(t, m.pending, "a request mined as an earlier version must be resolved, not still watched")

	require.Equal(t, original.Hash(), lastEvent(t, events).Receipt.TxHash,
		"the mined version should be reported")
}

// A request that loses its nonce moves above the queue rather than colliding
// with a live transaction of ours.
func TestCarriedOverRequestTakesANonceAboveTheOthers(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	first := send(m, s.submit) // nonce 0
	send(m, s.submit)          // nonce 1
	send(m, s.submit)          // nonce 2

	// Something else mined nonce 0, leaving 1 and 2 healthy.
	client.setAccountNonce(1)
	for nonce := uint64(0); nonce < 3; nonce++ {
		makeStale(t, m, nonce)
	}

	m.poll(context.Background())

	require.Equal(t, []uint64{1, 2, 3}, pendingNonces(m))

	// Nonce 3 is the carried request, so its original caller gets the answer.
	client.setReceipt(pendingWithNonce(t, m, 3).tx().Hash(), types.ReceiptStatusSuccessful)
	m.poll(context.Background())
	require.NotNil(t, lastEvent(t, first).Receipt)
}

func TestPollKeepsWatchingWhenReceiptLookupFails(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	events := send(m, s.submit)

	// A node error is not evidence about the transaction, so nothing resolves.
	client.setReceiptErr(errors.New("rpc timeout"))
	m.poll(context.Background())

	requireWatched(t, events)
	require.Len(t, m.pending, 1)
}

// The two outstanding cases mean different things to a caller: a queued request
// was never signed and cannot land, while a submitted one is in the pool and
// still might.
func TestShutdownResolvesEverythingOutstanding(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	submitted := send(m, s.submit)
	// Queued but never submitted, so shutdown has to resolve it too.
	queued := m.Send(s.submit)

	m.shutdown()

	require.ErrorIs(t, lastEvent(t, submitted).Err, ErrAbandoned)
	require.ErrorIs(t, lastEvent(t, queued).Err, ErrShutdown)
	require.Empty(t, m.pending)
}

func TestIgnoredEventChannelDoesNotBlockTheWorker(t *testing.T) {
	client := newFakeClient()
	m := newTestManager(t, client)
	s := &submitter{}

	// Deliberately drop the channel: most callers have nothing to do on
	// confirmation and the worker must not care.
	_ = send(m, s.submit)
	client.setReceipt(onlyPending(t, m).tx().Hash(), types.ReceiptStatusSuccessful)

	done := make(chan struct{})
	go func() {
		m.poll(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll blocked on events nobody is reading")
	}
	require.Empty(t, m.pending)
}

// The tests above drive submit and poll directly. These two run the real Start
// loop, the only thing covering the select over requests, ticks and
// cancellation.
func TestStartDrivesARequestToConfirmation(t *testing.T) {
	client := newFakeClient()
	client.accountNonce = 5
	key, err := crypto.HexToECDSA(testSigningKey)
	require.NoError(t, err)
	m, err := NewManager(client, key, testChainID, Config{PollInterval: 5 * time.Millisecond})
	require.NoError(t, err)
	s := &submitter{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, deferFn := service.RunBackground(ctx, m)
	defer deferFn()

	events := m.Send(s.submit)

	require.Eventually(t, func() bool { return s.lastTx() != nil },
		2*time.Second, 5*time.Millisecond, "the worker never submitted the request")
	tx := s.lastTx()
	require.Equal(t, uint64(5), tx.Nonce())
	client.setReceipt(tx.Hash(), types.ReceiptStatusSuccessful)

	require.Equal(t, tx.Hash(), lastEvent(t, events).Receipt.TxHash)
}

func TestStartResolvesOutstandingWorkOnCancellation(t *testing.T) {
	client := newFakeClient()
	key, err := crypto.HexToECDSA(testSigningKey)
	require.NoError(t, err)
	m, err := NewManager(client, key, testChainID, Config{PollInterval: time.Hour})
	require.NoError(t, err)
	s := &submitter{}

	ctx, cancel := context.WithCancel(context.Background())
	_, deferFn := service.RunBackground(ctx, m)
	defer deferFn()

	events := m.Send(s.submit)
	require.Eventually(t, func() bool { return s.lastTx() != nil },
		2*time.Second, 5*time.Millisecond)

	cancel()

	// lastEvent fails the test rather than hanging if shutdown leaves a caller
	// waiting on a channel that never fires.
	require.ErrorIs(t, lastEvent(t, events).Err, ErrAbandoned)
}

func TestFromIsDerivedFromTheSigningKey(t *testing.T) {
	key, err := crypto.HexToECDSA(testSigningKey)
	require.NoError(t, err)
	m := newTestManager(t, newFakeClient())
	require.Equal(t, crypto.PubkeyToAddress(key.PublicKey), m.From())
}
