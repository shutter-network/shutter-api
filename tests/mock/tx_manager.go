package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/shutter-network/shutter-api/internal/txmgr"
)

// MockTxManager stands in for txmgr.Manager. A fake rather than a testify mock,
// because what a test needs from it is the timing rather than the return value:
// Send has to invoke the submit closure and announce what comes back, which is
// what the real manager's worker goroutine does.
type MockTxManager struct {
	from ecommon.Address
	// Err is returned instead of submitting, standing in for a manager that could
	// not get the request onto the chain.
	Err error
	// Events is every channel Send handed out, so a test can drive a request past
	// submission by publishing a receipt on it.
	Events []chan txmgr.Event
}

func NewMockTxManager(from ecommon.Address) *MockTxManager {
	return &MockTxManager{from: from}
}

func (m *MockTxManager) From() ecommon.Address {
	return m.from
}

// Send submits immediately and announces the result, so a caller waiting for a
// hash finds one already there. The channel is left open, as the real one is
// until the transaction resolves.
func (m *MockTxManager) Send(submit txmgr.SubmitFunc) <-chan txmgr.Event {
	events := make(chan txmgr.Event, 8)
	m.Events = append(m.Events, events)

	if m.Err != nil {
		events <- txmgr.Event{Err: m.Err}
		close(events)
		return events
	}

	tx, err := submit(&bind.TransactOpts{From: m.from, Nonce: nil})
	if err != nil {
		events <- txmgr.Event{Err: err}
		close(events)
		return events
	}
	events <- txmgr.Event{Tx: tx}
	return events
}

// Resolve ends the most recent request with a receipt, as the manager does once
// the transaction is mined.
func (m *MockTxManager) Resolve(receipt *types.Receipt) {
	events := m.Events[len(m.Events)-1]
	events <- txmgr.Event{Receipt: receipt}
	close(events)
}

// Reset drops the requests remembered from earlier tests.
func (m *MockTxManager) Reset() {
	m.Events = nil
	m.Err = nil
}
