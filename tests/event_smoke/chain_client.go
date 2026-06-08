package eventsmoke

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func emitEvent(cfg *Config, emitSig string, emitArgs []string) (string, error) {
	cmd := []string{
		"send", "--async", "--json",
		"--rpc-url", cfg.RPCURL,
		"--private-key", cfg.PrivateKey,
		cfg.PlaygroundAddr,
		emitSig,
	}
	cmd = append(cmd, emitArgs...)

	out, err := runCmd("cast", cmd...)
	if err != nil {
		return "", err
	}

	var m map[string]any
	if json.Unmarshal([]byte(out), &m) == nil {
		if h := str(m["transactionHash"]); h != "" {
			return h, nil
		}
	}
	if h := txHashRe.FindString(out); h != "" {
		return h, nil
	}
	return "", fmt.Errorf("tx hash not found in cast output: %s", strings.TrimSpace(out))
}

func waitReceiptBlock(cfg *Config, txHash string) (int64, error) {
	deadline := time.Now().Add(time.Duration(cfg.PollSeconds) * time.Second)
	for time.Now().Before(deadline) {
		out, err := runCmd("cast", "receipt", "--json", "--rpc-url", cfg.RPCURL, txHash)
		if err == nil {
			var m map[string]any
			if json.Unmarshal([]byte(out), &m) == nil {
				if b := str(m["blockNumber"]); b != "" {
					if v := parseBlockNumber(b); v > 0 {
						return v, nil
					}
				}
			}
		}
		time.Sleep(time.Duration(cfg.PollInterval) * time.Second)
	}
	return 0, fmt.Errorf("timeout waiting receipt for tx %s", txHash)
}

func waitBlockGreater(cfg *Config, target int64) error {
	deadline := time.Now().Add(time.Duration(cfg.PollSeconds) * time.Second)
	for time.Now().Before(deadline) {
		out, err := runCmd("cast", "block-number", "--rpc-url", cfg.RPCURL)
		if err == nil {
			cur, _ := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
			if cur > target {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout waiting for block > %d", target)
}

func parseBlockNumber(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(s, "0x") {
		v, _ := strconv.ParseInt(strings.TrimPrefix(s, "0x"), 16, 64)
		return v
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}