package time_stress

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// poolEntry is one pre-registered identity used by read-only workers. The
// decryption key is live from the moment the setup phase finishes polling for
// it, so a read-only loop never has to wait for one.
type poolEntry struct {
	Prefix    string
	Identity  string
	Eon       uint64
	Timestamp int64
}

// buildPool registers PoolSize identities concurrently and polls each until its
// decryption key is available, so the stress loop that follows is pure reads.
//
// Setup failures are fatal: a stress run against a partially-populated pool
// would be measuring something nobody asked for.
func buildPool(ctx context.Context, c *client, cfg Config, logger *log.Logger) ([]poolEntry, error) {
	type regResult struct {
		entry poolEntry
		err   error
	}

	timestamp := time.Now().Add(cfg.PoolSetupLead).Unix()
	deadline := time.Unix(timestamp, 0)

	// Register concurrently. Each registration is an on-chain tx so throughput
	// is bounded by the API's nonce/gas path — nothing to gain from thousands
	// in flight at once, but doing them sequentially would also be wasteful.
	results := make(chan regResult, cfg.PoolSize)
	sem := make(chan struct{}, 4) // modest concurrency on setup

	wg := sync.WaitGroup{}
	for i := 0; i < cfg.PoolSize; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			prefix, err := randomPrefix()
			if err != nil {
				results <- regResult{err: fmt.Errorf("prefix %d: %w", i, err)}
				return
			}
			data, err := c.getDataForEncryption(ctx, cfg.SignerAddress.Hex(), prefix)
			if err != nil {
				results <- regResult{err: fmt.Errorf("get_data_for_encryption %d: %w", i, err)}
				return
			}
			reg, err := c.registerIdentity(ctx, timestamp, prefix)
			if err != nil {
				results <- regResult{err: fmt.Errorf("register_identity %d: %w", i, err)}
				return
			}
			if reg.Identity != data.Identity {
				results <- regResult{err: fmt.Errorf("identity mismatch %d: %s vs %s", i, reg.Identity, data.Identity)}
				return
			}
			results <- regResult{entry: poolEntry{Prefix: prefix, Identity: data.Identity, Eon: data.Eon, Timestamp: timestamp}}
		}(i)
	}

	go func() { wg.Wait(); close(results) }()

	pool := make([]poolEntry, 0, cfg.PoolSize)
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		pool = append(pool, r.entry)
	}

	// Wait for the decryption timestamp, then poll for each key. Doing it in
	// parallel is fine — read side of the API, no on-chain cost.
	if wait := time.Until(deadline); wait > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	giveUp := deadline.Add(cfg.PoolSetupPoll)
	errs := make(chan error, len(pool))
	for i := range pool {
		go func(i int) {
			for {
				_, desc, err := c.getDecryptionKey(ctx, pool[i].Identity)
				if err != nil {
					errs <- fmt.Errorf("get_decryption_key for %s: %w", pool[i].Identity, err)
					return
				}
				if desc == "" {
					errs <- nil
					return
				}
				if time.Now().After(giveUp) {
					errs <- fmt.Errorf("key for %s never arrived: %s", pool[i].Identity, desc)
					return
				}
				select {
				case <-ctx.Done():
					errs <- ctx.Err()
					return
				case <-time.After(cfg.PollInterval):
				}
			}
		}(i)
	}

	for range pool {
		if err := <-errs; err != nil {
			return nil, err
		}
	}
	return pool, nil
}
