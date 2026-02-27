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