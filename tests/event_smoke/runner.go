package eventsmoke

import (
	"fmt"
	"strings"
	"time"
)

type stepMeta struct {
	Identity       string
	Eon            int64
	Prefix         string
	TriggerDef     string
	RegisterTxHash string
	EventTxHash    string
}

func runCase(cfg *Config, tc TestCase) Result {
	meta := &stepMeta{}

	fmt.Printf("[%s] compile\n", tc.Name)
	td, err := compileTrigger(cfg, tc.Event, tc.Args)
	if err != nil {
		return Result{tc.Name, "FAIL", "compile: " + err.Error()}
	}
	meta.TriggerDef = td
	logf(cfg, "[%s] trigger=%s", tc.Name, shortHex(td, 26))

	if tc.MultiReg > 1 {
		return runMultiReg(cfg, tc, td)
	}

	fmt.Printf("[%s] register\n", tc.Name)
	identity, eon, regTx, prefix, err := registerIdentity(cfg, td)
	if err != nil {
		return Result{tc.Name, "FAIL", "register: " + err.Error()}
	}
	meta.Identity = identity
	meta.Eon = eon
	meta.RegisterTxHash = regTx
	meta.Prefix = prefix
	logf(cfg, "[%s] identity=%s eon=%d prefix=%s regTx=%s", tc.Name, identity, eon, prefix, regTx)

	if cfg.WaitRegReceipt {
		fmt.Printf("[%s] wait registration receipt\n", tc.Name)
		regBlock, err := waitReceiptBlock(cfg, regTx)
		if err != nil {
			return Result{tc.Name, "FAIL", "registration receipt: " + err.Error()}
		}
		_ = waitBlockGreater(cfg, regBlock)
	} else {
		fmt.Printf("[%s] registration tx=%s (sleep %s)\n", tc.Name, regTx, cfg.RegistrationDelay)
		time.Sleep(cfg.RegistrationDelay)
	}

	fmt.Printf("[%s] emit\n", tc.Name)
	evTx, err := emitEvent(cfg, tc.EmitSig, tc.EmitArg)
	if err != nil {
		return Result{tc.Name, "FAIL", "emit: " + err.Error()}
	}
	meta.EventTxHash = evTx
	logf(cfg, "[%s] emitTx=%s sig=%s args=%v", tc.Name, evTx, tc.EmitSig, tc.EmitArg)

	evBlock, err := waitReceiptBlock(cfg, evTx)
	if err != nil {
		return Result{tc.Name, "FAIL", "event receipt: " + err.Error()}
	}
	logf(cfg, "[%s] eventBlock=%d", tc.Name, evBlock)

	fmt.Printf("[%s] poll key\n", tc.Name)
	deadline := time.Now().Add(time.Duration(cfg.PollSeconds) * time.Second)
	lastErr := "decryption key not ready"
	timeouts := 0
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		key, msg, ok := getDecryptionKey(cfg, meta.Identity, meta.Eon)
		if ok {
			if tc.ExpectKey {
				return Result{
					Name:   tc.Name,
					Status: "PASS",
					Reason: fmt.Sprintf("identity=%s eon=%d key=%s", meta.Identity, meta.Eon, shortHex(key, 18)),
				}
			}
			return Result{
				Name:   tc.Name,
				Status: "FAIL",
				Reason: fmt.Sprintf("unexpected key (expected no key): identity=%s eon=%d", meta.Identity, meta.Eon),
			}
		}

		lastErr = msg
		logf(cfg, "[%s] pending attempt=%d msg=%s", tc.Name, attempt, msg)

		if strings.Contains(strings.ToLower(msg), "timeout") {
			timeouts++
			if timeouts >= cfg.MaxConsecTimeouts {
				return Result{
					Name:   tc.Name,
					Status: "FAIL",
					Reason: fmt.Sprintf("aborted after %d timeouts: %s", timeouts, msg),
				}
			}
		} else {
			timeouts = 0
		}

		if isTerminalNotFound(msg) {
			time.Sleep(time.Duration(cfg.PollInterval) * time.Second)
			continue
		}

		if !isTransient(msg) {
			return Result{
				Name:   tc.Name,
				Status: "FAIL",
				Reason: fmt.Sprintf("non-transient error: %s", msg),
			}
		}

		time.Sleep(time.Duration(cfg.PollInterval) * time.Second)
	}

	if tc.ExpectKey {
		return Result{
			Name:   tc.Name,
			Status: "FAIL",
			Reason: fmt.Sprintf("timeout polling key: identity=%s eon=%d last=%s", meta.Identity, meta.Eon, lastErr),
		}
	}
	return Result{
		Name:   tc.Name,
		Status: "PASS",
		Reason: fmt.Sprintf("timeout with no key (expected no key): identity=%s eon=%d", meta.Identity, meta.Eon),
	}
}

func runMultiReg(cfg *Config, tc TestCase, triggerDef string) Result {
	n := tc.MultiReg
	type regEntry struct {
		identity string
		eon      int64
	}
	regs := make([]regEntry, 0, n)

	for i := 0; i < n; i++ {
		fmt.Printf("[%s] register %d/%d\n", tc.Name, i+1, n)
		identity, eon, regTx, prefix, err := registerIdentity(cfg, triggerDef)
		if err != nil {
			return Result{tc.Name, "FAIL", fmt.Sprintf("register %d: %s", i+1, err.Error())}
		}
		logf(cfg, "[%s] reg[%d] identity=%s eon=%d prefix=%s", tc.Name, i+1, identity, eon, prefix)

		if cfg.WaitRegReceipt {
			fmt.Printf("[%s] wait registration receipt %d/%d\n", tc.Name, i+1, n)
			regBlock, err := waitReceiptBlock(cfg, regTx)
			if err != nil {
				return Result{tc.Name, "FAIL", fmt.Sprintf("registration receipt %d: %s", i+1, err.Error())}
			}
			_ = waitBlockGreater(cfg, regBlock)
		} else {
			fmt.Printf("[%s] reg[%d] tx=%s (sleep %s)\n", tc.Name, i+1, regTx, cfg.RegistrationDelay)
			time.Sleep(cfg.RegistrationDelay)
		}
		regs = append(regs, regEntry{identity, eon})
	}

	fmt.Printf("[%s] emit\n", tc.Name)
	evTx, err := emitEvent(cfg, tc.EmitSig, tc.EmitArg)
	if err != nil {
		return Result{tc.Name, "FAIL", "emit: " + err.Error()}
	}
	logf(cfg, "[%s] emitTx=%s sig=%s args=%v", tc.Name, evTx, tc.EmitSig, tc.EmitArg)

	evBlock, err := waitReceiptBlock(cfg, evTx)
	if err != nil {
		return Result{tc.Name, "FAIL", "event receipt: " + err.Error()}
	}
	logf(cfg, "[%s] eventBlock=%d", tc.Name, evBlock)

	fmt.Printf("[%s] poll %d keys\n", tc.Name, n)
	deadline := time.Now().Add(time.Duration(cfg.PollSeconds) * time.Second)
	keys := make(map[string]string, n) // identity -> key
	timeouts := make(map[string]int, n)

	for time.Now().Before(deadline) && len(keys) < n {
		for _, reg := range regs {
			if _, found := keys[reg.identity]; found {
				continue
			}
			key, msg, ok := getDecryptionKey(cfg, reg.identity, reg.eon)
			if ok {
				keys[reg.identity] = key
				logf(cfg, "[%s] got key for identity=%s key=%s", tc.Name, shortHex(reg.identity, 10), shortHex(key, 18))
				continue
			}
			logf(cfg, "[%s] pending identity=%s msg=%s", tc.Name, shortHex(reg.identity, 10), msg)

			if strings.Contains(strings.ToLower(msg), "timeout") {
				timeouts[reg.identity]++
				if timeouts[reg.identity] >= cfg.MaxConsecTimeouts {
					return Result{
						Name:   tc.Name,
						Status: "FAIL",
						Reason: fmt.Sprintf("aborted after %d timeouts for identity %s: %s", timeouts[reg.identity], reg.identity, msg),
					}
				}
			} else {
				timeouts[reg.identity] = 0
			}

			if !isTransient(msg) && !isTerminalNotFound(msg) {
				return Result{
					Name:   tc.Name,
					Status: "FAIL",
					Reason: fmt.Sprintf("non-transient error for identity %s: %s", reg.identity, msg),
				}
			}
		}
		if len(keys) < n {
			time.Sleep(time.Duration(cfg.PollInterval) * time.Second)
		}
	}

	if len(keys) < n {
		missing := make([]string, 0, n-len(keys))
		for _, reg := range regs {
			if _, found := keys[reg.identity]; !found {
				missing = append(missing, shortHex(reg.identity, 10))
			}
		}
		return Result{
			Name:   tc.Name,
			Status: "FAIL",
			Reason: fmt.Sprintf("timeout: only %d/%d keys received, missing identities: %v", len(keys), n, missing),
		}
	}

	// assert all keys are distinct
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