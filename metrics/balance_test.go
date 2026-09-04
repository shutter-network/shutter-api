package metrics

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockBalanceReader is local to this test: the poller needs a single method,
// while tests/mock.MockEthClient serves the usecase's wider interface.
type mockBalanceReader struct {
	mock.Mock
}

func (m *mockBalanceReader) BalanceAt(ctx context.Context, account ecommon.Address, blockNumber *big.Int) (*big.Int, error) {
	args := m.Called(ctx, account, blockNumber)
	balance, _ := args.Get(0).(*big.Int)
	return balance, args.Error(1)
}

// Deliberately not a real signer address.
var testSignerAddress = ecommon.HexToAddress("0x1111111111111111111111111111111111111111")

// A registered-but-never-read balance must expose nothing at all. Publishing a
// zero would be read as an empty signer account.
func TestBalanceIsAbsentBeforeTheFirstRead(t *testing.T) {
	require.Zero(t, testutil.CollectAndCount(newSignerBalanceGauge()))
}

func TestPollPublishesBalanceInEther(t *testing.T) {
	// 1.5 ether, to catch a big.Int quotient truncating the fraction away.
	wei := new(big.Int).Add(
		new(big.Int).SetUint64(1e18),
		new(big.Int).SetUint64(5e17),
	)

	client := &mockBalanceReader{}
	client.On("BalanceAt", mock.Anything, testSignerAddress, (*big.Int)(nil)).Return(wei, nil)

	NewBalancePoller(client, testSignerAddress).poll(context.Background())

	require.InDelta(t, 1.5, testutil.ToFloat64(SignerBalanceEther.WithLabelValues()), 1e-9)
	client.AssertExpectations(t)
}

func TestPollLeavesGaugeUntouchedOnError(t *testing.T) {
	SignerBalanceEther.WithLabelValues().Set(2)
	failuresBefore := testutil.ToFloat64(FailedRPCCalls)

	client := &mockBalanceReader{}
	client.On("BalanceAt", mock.Anything, testSignerAddress, (*big.Int)(nil)).
		Return(nil, errors.New("rpc unavailable"))

	NewBalancePoller(client, testSignerAddress).poll(context.Background())

	// A zero here would read as an empty account and fire a false alert.
	require.InDelta(t, 2.0, testutil.ToFloat64(SignerBalanceEther.WithLabelValues()), 1e-9)
	require.Equal(t, failuresBefore+1, testutil.ToFloat64(FailedRPCCalls))
}

// The read must carry its own deadline, so a hung RPC cannot stall the loop
// and stop every later poll.
func TestPollBoundsTheReadWithATimeout(t *testing.T) {
	var got context.Context

	client := &mockBalanceReader{}
	client.On("BalanceAt", mock.Anything, testSignerAddress, (*big.Int)(nil)).
		Run(func(args mock.Arguments) { got = args.Get(0).(context.Context) }).
		Return(big.NewInt(0), nil)

	NewBalancePoller(client, testSignerAddress).poll(context.Background())

	deadline, ok := got.Deadline()
	require.True(t, ok, "read was made without a deadline")
	require.LessOrEqual(t, time.Until(deadline), balancePollTimeout)
}
