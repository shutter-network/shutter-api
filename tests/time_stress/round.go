package time_stress

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var plaintext = []byte("shutter time_stress runner")

const (
	StagePrefix   = "generate_prefix"
	StageGetData  = "get_data_for_encryption"
	StageEncrypt  = "encrypt"
	StageRegister = "register_identity"
	StagePoll     = "poll_decryption_key"
	StageGetKey   = "get_decryption_key" // single read in read-only mode
	StageDecrypt  = "decrypt"
	StageVerify   = "verify_plaintext"
)

// Stages enumerates every stage name we observe into histograms, so metrics
// label values are stable across runs.
var Stages = []string{StageGetData, StageEncrypt, StageRegister, StagePoll, StageGetKey, StageDecrypt}

// Result is one round, in either mode.
type Result struct {
	Worker  int
	Round   int
	Mode    Mode
	Pass    bool
	Stage   string
	Err     error
	// StageDurations records how long each stage took, in the order they ran.
	// Reported as "stage=duration" pairs in metrics so slow stages stand out.
	StageDurations map[string]time.Duration
	// Latency has different meaning per mode: full-round = key availability
	// minus the decryption timestamp; read-only = total time of the two reads.
	Latency   time.Duration
	Eon       uint64
	Identity  string
	TxHash    string
	Timestamp int64
	LastPoll  string
}

func (r Result) String() string {
	line := fmt.Sprintf("w=%d round=%d", r.Worker, r.Round)
	if r.Pass {
		line += fmt.Sprintf(" PASS latency=%s", r.Latency.Round(time.Millisecond))
	} else {
		line += fmt.Sprintf(" FAIL stage=%s err=%v", r.Stage, r.Err)
	}
	for _, name := range Stages {
		if d, ok := r.StageDurations[name]; ok {
			line += fmt.Sprintf(" %s=%s", name, d.Round(time.Millisecond))
		}
	}
	if r.Identity != "" {
		line += " identity=" + r.Identity
	}
	if r.TxHash != "" {
		line += " tx=" + r.TxHash
	}
	if !r.Pass && r.LastPoll != "" {
		line += fmt.Sprintf(" last_poll=%q", r.LastPoll)
	}
	return line
}

// runFullRound is one end-to-end round: register, encrypt, wait, poll, decrypt,
// verify. Mirrors continuous.RunRound closely but records per-stage durations.
func runFullRound(ctx context.Context, c *client, cfg Config, worker, round int) Result {
	res := Result{Worker: worker, Round: round, Mode: ModeFull, StageDurations: map[string]time.Duration{}}

	prefix, err := randomPrefix()
	if err != nil {
		res.Stage, res.Err = StagePrefix, err
		return res
	}

	t0 := time.Now()
	data, err := c.getDataForEncryption(ctx, cfg.SignerAddress.Hex(), prefix)
	res.StageDurations[StageGetData] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageGetData, err
		return res
	}
	if data.EonKey == "" || data.Identity == "" {
		res.Stage, res.Err = StageGetData, fmt.Errorf("empty eon key or identity — DKG may not have completed for eon %d", data.Eon)
		return res
	}
	res.Eon, res.Identity = data.Eon, data.Identity

	t0 = time.Now()
	encrypted, err := encryptTo(data)
	res.StageDurations[StageEncrypt] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageEncrypt, err
		return res
	}

	timestamp := time.Now().Add(cfg.Lead).Unix()
	res.Timestamp = timestamp
	t0 = time.Now()
	reg, err := c.registerIdentity(ctx, timestamp, prefix)
	res.StageDurations[StageRegister] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageRegister, err
		return res
	}
	res.TxHash = reg.TxHash
	if reg.Identity != data.Identity {
		res.Stage, res.Err = StageRegister, fmt.Errorf("registered identity %s does not match %s", reg.Identity, data.Identity)
		return res
	}

	deadline := time.Unix(timestamp, 0)
	if wait := time.Until(deadline); wait > 0 {
		select {
		case <-ctx.Done():
			res.Stage, res.Err = StagePoll, ctx.Err()
			return res
		case <-time.After(wait):
		}
	}

	t0 = time.Now()
	key, lastPoll, err := poll(ctx, c, cfg, data.Identity, deadline)
	res.StageDurations[StagePoll] = time.Since(t0)
	res.LastPoll = lastPoll
	if err != nil {
		res.Stage, res.Err = StagePoll, err
		return res
	}
	res.Latency = time.Since(deadline)

	t0 = time.Now()
	decrypted, err := decryptWith(encrypted, key.DecryptionKey)
	res.StageDurations[StageDecrypt] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageDecrypt, err
		return res
	}
	if string(decrypted) != string(plaintext) {
		res.Stage, res.Err = StageVerify, fmt.Errorf("decrypted %q, expected %q", decrypted, plaintext)
		return res
	}

	res.Pass = true
	return res
}

// runReadRound is one read-only round against a pre-registered identity: fetch
// its encryption data and its decryption key. No on-chain tx, no polling — this
// is the path to drive if the goal is to stress the API's read endpoints (and
// the keypers' RPC/WS fan-out behind them) rather than its tx-submission side.
func runReadRound(ctx context.Context, c *client, cfg Config, worker, round int, p poolEntry) Result {
	res := Result{
		Worker:         worker,
		Round:          round,
		Mode:           ModeReadOnly,
		StageDurations: map[string]time.Duration{},
		Identity:       p.Identity,
		Eon:            p.Eon,
		Timestamp:      p.Timestamp,
	}

	start := time.Now()

	t0 := time.Now()
	data, err := c.getDataForEncryption(ctx, cfg.SignerAddress.Hex(), p.Prefix)
	res.StageDurations[StageGetData] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageGetData, err
		return res
	}
	// A pool identity whose derived identity suddenly disagrees with its
	// cached one is a server-side bug worth surfacing, not a transient.
	if data.Identity != p.Identity {
		res.Stage, res.Err = StageGetData, fmt.Errorf("identity drift: pool=%s api=%s", p.Identity, data.Identity)
		return res
	}

	t0 = time.Now()
	key, desc, err := c.getDecryptionKey(ctx, p.Identity)
	res.StageDurations[StageGetKey] = time.Since(t0)
	if err != nil {
		res.Stage, res.Err = StageGetKey, err
		return res
	}
	if desc != "" {
		res.Stage, res.Err = StageGetKey, fmt.Errorf("%s", desc)
		res.LastPoll = desc
		return res
	}
	if key.DecryptionKey == "" {
		res.Stage, res.Err = StageGetKey, fmt.Errorf("200 with empty decryption_key")
		return res
	}

	res.Latency = time.Since(start)
	res.Pass = true
	return res
}

// poll asks for the decryption key until it arrives or PollTimeout elapses past
// the decryption timestamp.
func poll(ctx context.Context, c *client, cfg Config, identity string, deadline time.Time) (decryptionKey, string, error) {
	giveUp := deadline.Add(cfg.PollTimeout)
	var last string

	for {
		key, desc, err := c.getDecryptionKey(ctx, identity)
		if err != nil {
			return decryptionKey{}, last, err
		}
		if desc == "" {
			if key.DecryptionKey == "" {
				return decryptionKey{}, last, fmt.Errorf("200 with empty decryption_key")
			}
			return key, last, nil
		}
		last = desc

		if time.Now().After(giveUp) {
			return decryptionKey{}, last, fmt.Errorf("no key %s past the decryption timestamp; last response: %s", cfg.PollTimeout, last)
		}
		select {
		case <-ctx.Done():
			return decryptionKey{}, last, ctx.Err()
		case <-time.After(cfg.PollInterval):
		}
	}
}

func randomPrefix() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("generate identity prefix: %w", err)
	}
	return "0x" + hex.EncodeToString(b), nil
}

func encryptTo(data dataForEncryption) (*shcrypto.EncryptedMessage, error) {
	identityBytes, err := hexBytes(data.Identity)
	if err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	eonKeyBytes, err := hexBytes(data.EonKey)
	if err != nil {
		return nil, fmt.Errorf("decode eon key: %w", err)
	}
	eonPublicKey := &shcrypto.EonPublicKey{}
	if err := eonPublicKey.Unmarshal(eonKeyBytes); err != nil {
		return nil, fmt.Errorf("unmarshal eon key: %w", err)
	}
	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("random sigma: %w", err)
	}
	epochID := shcrypto.ComputeEpochID(identityBytes)
	return shcrypto.Encrypt(plaintext, eonPublicKey, epochID, sigma), nil
}

func decryptWith(encrypted *shcrypto.EncryptedMessage, keyHex string) ([]byte, error) {
	keyBytes, err := hexBytes(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode decryption key: %w", err)
	}
	key := &shcrypto.EpochSecretKey{}
	if err := key.Unmarshal(keyBytes); err != nil {
		return nil, fmt.Errorf("unmarshal decryption key: %w", err)
	}
	return encrypted.Decrypt(key)
}

func hexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}
