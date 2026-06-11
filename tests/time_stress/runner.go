package timestress

import (
	"fmt"
	"strings"
	"time"
)

func runCase(cfg *Config, tc TestCase) Result {
	n := tc.Count
	decryptionTimestamp := uint64(time.Now().Add(cfg.TimeDecryptionOffset).Unix())
	fmt.Printf("[%s] target decryptionTimestamp=%d (offset=%s)\n", tc.Name, decryptionTimestamp, cfg.TimeDecryptionOffset)

	type regEntry struct {
		idx      int
		identity string
		txHash   string
		prefix   string
		err      error
	}

	fmt.Printf("[%s] registering %d identities in parallel (concurrency=%d)\n", tc.Name, n, cfg.RegConcurrency)
	regCh := make(chan regEntry, n)
	sem := make(chan struct{}, cfg.RegConcurrency)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			identity, txHash, prefix, err := registerTimeIdentity(cfg, decryptionTimestamp)
			regCh <- regEntry{i, identity, txHash, prefix, err}
		}()
	}

	type reg struct {
		identity string
	}
	regs := make([]reg, 0, n)
	for i := 0; i < n; i++ {
		r := <-regCh
		if r.err != nil {
			return Result{tc.Name, "FAIL", fmt.Sprintf("register %d: %s", r.idx+1, r.err.Error())}
		}
		logf(cfg, "[%s] reg[%d] identity=%s prefix=%s", tc.Name, r.idx+1, r.identity, r.prefix)
		regs = append(regs, reg{r.identity})
	}

	fmt.Printf("[%s] all %d registrations submitted (sleep %s)\n", tc.Name, n, cfg.RegistrationDelay)
	time.Sleep(cfg.RegistrationDelay)

	targetTime := time.Unix(int64(decryptionTimestamp), 0)
	if remaining := time.Until(targetTime); remaining > 0 {
		fmt.Printf("[%s] waiting %s for decryption timestamp\n", tc.Name, remaining.Round(time.Second))
		time.Sleep(remaining)
	}

	if !tc.ExpectKeys {
		return Result{
			Name:   tc.Name,
			Status: "PASS",
			Reason: fmt.Sprintf("registered %d identities, no keys expected", n),
		}
	}

	fmt.Printf("[%s] polling for %d keys\n", tc.Name, n)
	deadline := time.Now().Add(time.Duration(cfg.PollSeconds) * time.Second)
	keys := make(map[string]string, n) // identity -> key
	timeouts := make(map[string]int, n)

	for time.Now().Before(deadline) && len(keys) < n {
		for _, r := range regs {
			if _, found := keys[r.identity]; found {
				continue
			}
			key, msg, ok := getTimeDecryptionKey(cfg, r.identity)
			if ok {
				keys[r.identity] = key
				logf(cfg, "[%s] got key for identity=%s key=%s", tc.Name, shortHex(r.identity, 10), shortHex(key, 18))
				continue
			}
			logf(cfg, "[%s] pending identity=%s msg=%s", tc.Name, shortHex(r.identity, 10), msg)

			if strings.Contains(strings.ToLower(msg), "timeout") {
				timeouts[r.identity]++
				if timeouts[r.identity] >= cfg.MaxConsecTimeouts {
					return Result{
						Name:   tc.Name,
						Status: "FAIL",
						Reason: fmt.Sprintf("aborted after %d timeouts for identity %s: %s", timeouts[r.identity], r.identity, msg),
					}
				}
			} else {
				timeouts[r.identity] = 0
			}

			if !isTransient(msg) && !isTerminalNotFound(msg) {
				return Result{
					Name:   tc.Name,
					Status: "FAIL",
					Reason: fmt.Sprintf("non-transient error for identity %s: %s", r.identity, msg),
				}
			}
		}
		if len(keys) < n {
			time.Sleep(time.Duration(cfg.PollInterval) * time.Second)
		}
	}

	if len(keys) < n {
		missing := make([]string, 0, n-len(keys))
		for _, r := range regs {
			if _, found := keys[r.identity]; !found {
				missing = append(missing, shortHex(r.identity, 10))
			}
		}
		return Result{
			Name:   tc.Name,
			Status: "FAIL",
			Reason: fmt.Sprintf("timeout: only %d/%d keys received, missing: %v", len(keys), n, missing),
		}
	}

	seen := make(map[string]string, n) // key -> identity
	for identity, key := range keys {
		if prev, dup := seen[key]; dup {
			return Result{
				Name:   tc.Name,
				Status: "FAIL",
				Reason: fmt.Sprintf("duplicate key %s for identities %s and %s", shortHex(key, 18), shortHex(prev, 10), shortHex(identity, 10)),
			}
		}
		seen[key] = identity
	}

	return Result{
		Name:   tc.Name,
		Status: "PASS",
		Reason: fmt.Sprintf("received %d distinct decryption keys for %d registrations", n, n),
	}
}

func isTerminalNotFound(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "http 404") ||
		strings.Contains(m, "doesn't exist") ||
		strings.Contains(m, "doesnt exist") ||
		strings.Contains(m, "not found")
}

func isTransient(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "too early") ||
		strings.Contains(m, "not ready") ||
		strings.Contains(m, "timeout")
}
