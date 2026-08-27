package metrics

import (
	"context"
	"math/big"
	"time"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
)

const (
	balancePollInterval = 60 * time.Second
	balancePollTimeout  = 10 * time.Second
)

// weiPerEther is the divisor turning a wei balance into ether.
var weiPerEther = new(big.Float).SetFloat64(1e18)

var SignerBalanceEther = newSignerBalanceGauge()

// A GaugeVec with no labels, so the series stays absent until a balance has
// been read. A plain Gauge would be registered holding 0, and a restart while
// the RPC endpoint is down would publish 0 ether and fire the low-balance
// alert. The exposed series is the same either way.
func newSignerBalanceGauge() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "shutter_api",
			Name:      "signer_balance_ether",
			Help:      "Balance of the signer account in ether.",
		},
		[]string{},
	)
}

func initBalanceMetrics() {
	prometheus.MustRegister(SignerBalanceEther)
}

// BalanceReader reads an account balance from the chain. It is the single
// method of ethclient.Client that the poller needs.
type BalanceReader interface {
	BalanceAt(ctx context.Context, account ecommon.Address, blockNumber *big.Int) (*big.Int, error)
}

// BalancePoller publishes the signer's balance as a gauge. The signer pays gas
// for every identity registration, so an empty account takes registration down;
// without this the service spends from an account it cannot observe.
type BalancePoller struct {
	client  BalanceReader
	address ecommon.Address
}

func NewBalancePoller(client BalanceReader, address ecommon.Address) *BalancePoller {
	return &BalancePoller{client: client, address: address}
}

func (p *BalancePoller) Start(ctx context.Context, runner service.Runner) error {
	runner.Go(func() error {
		ticker := time.NewTicker(balancePollInterval)
		defer ticker.Stop()

		// Publish once up front so the series exists from the first scrape
		// rather than only after a full interval.
		p.poll(ctx)

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				p.poll(ctx)
			}
		}
	})
	return nil
}

// poll reads the balance and updates the gauge. A failed read leaves the gauge
// at its previous value: publishing a zero would look like an empty account and
// fire the very alert this metric exists to raise. Errors are never returned,
// because the poller shares an error group with the API and a transient RPC
// failure must not shut the service down.
func (p *BalancePoller) poll(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, balancePollTimeout)
	defer cancel()

	wei, err := p.client.BalanceAt(ctx, p.address, nil)
	if err != nil {
		// Cancellations should not count as failed RPC calls. They are
		// detected by checking if the parent context is done.
		if parent.Err() != nil {
			return
		}
		log.Err(err).Str("address", p.address.Hex()).Msg("failed to query signer balance")
		FailedRPCCalls.Inc()
		return
	}

	ether, _ := new(big.Float).Quo(new(big.Float).SetInt(wei), weiPerEther).Float64()
	SignerBalanceEther.WithLabelValues().Set(ether)
}
