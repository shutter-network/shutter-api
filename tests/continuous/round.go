package continuous

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/shutter-network/shutter/shlib/shcrypto"
)

// plaintext is what every round encrypts and expects back. Fixed rather than
// random so a mismatch is obvious in a log rather than needing correlation.
var plaintext = []byte("shutter continuous monitor")

// Stage names, reported on failure so a log line says where a round broke without
// needing the error text parsed.
const (
	StagePrefix   = "generate_prefix"
	StageGetData  = "get_data_for_encryption"
	StageEncrypt  = "encrypt"
	StageRegister = "register_identity"
	StagePoll     = "poll_decryption_key"
	StageDecrypt  = "decrypt"
	StageVerify   = "verify_plaintext"
)

// Result is the outcome of one round.
type Result struct {
	Round     int
	Pass      bool
	Stage     string        // set only on failure
	Err       error         // set only on failure
	Latency   time.Duration // key availability minus the decryption timestamp
	Eon       uint64
	Identity  string
	TxHash    string
	Timestamp int64  // the decryption timestamp this round registered
	LastPoll  string // the API's last non-200 description, useful when a round fails
}

// String renders one log line.
//
// Identities and transaction hashes are logged in full, not elided. The reason to
// keep these logs at all is being able to take a round from six hours ago and look
// it up in the registry or on the explorer, and a truncated hash cannot be pasted
// into either. At one round a minute a day of this is about 200KB.
func (r Result) String() string {
	line := fmt.Sprintf("round=%d", r.Round)
	if r.Pass {
		line += fmt.Sprintf(" PASS latency=%s", r.Latency.Round(time.Millisecond))
	} else {
		line += fmt.Sprintf(" FAIL stage=%s err=%v", r.Stage, r.Err)
	}
	if r.Eon != 0 {
		line += fmt.Sprintf(" eon=%d", r.Eon)
	}
	if r.Timestamp != 0 {
		line += fmt.Sprintf(" ts=%d", r.Timestamp)
	}
	if r.Identity != "" {
		line += " identity=" + r.Identity
	}
	if r.TxHash != "" {
		line += " tx=" + r.TxHash
	}
	if r.LastPoll != "" {
		line += fmt.Sprintf(" last_poll=%q", r.LastPoll)
	}
	return line
}

// RunRound performs one full round: derive an identity, encrypt to it, register
// it, wait for the decryption timestamp, fetch the released key and decrypt.
//
// It returns a Result rather than an error. A failed round is data, not a fault —
// the caller records it and continues, so one bad round cannot end a long run.
func RunRound(ctx context.Context, c *client, cfg Config, round int) Result {
	res := Result{Round: round}

	prefixBytes := make([]byte, 32)
	if _, err := cryptorand.Read(prefixBytes); err != nil {
		res.Stage, res.Err = StagePrefix, fmt.Errorf("generate identity prefix: %w", err)
		return res
	}
	prefix := "0x" + hex.EncodeToString(prefixBytes)

	// 1. Ask the API for the eon key and the identity this prefix maps to. The
	//    address must be the API's own signer, since the API registers on our
	//    behalf and the contract derives the identity from msg.sender.
	data, err := c.getDataForEncryption(ctx, cfg.SignerAddress.Hex(), prefix)
	if err != nil {
		res.Stage, res.Err = StageGetData, err
		return res
	}
	if data.EonKey == "" || data.Identity == "" {
		res.Stage, res.Err = StageGetData, fmt.Errorf("empty eon key or identity — DKG may not have completed for eon %d", data.Eon)
		return res
	}
	res.Eon, res.Identity = data.Eon, data.Identity

	// 2. Encrypt locally. This is the part that makes the monitor meaningful: a
	//    round only passes if the released key actually decrypts what we encrypted.
	encrypted, err := encryptTo(data)
	if err != nil {
		res.Stage, res.Err = StageEncrypt, err
		return res
	}

	// 3. Register, with the decryption timestamp Lead ahead of now.
	timestamp := time.Now().Add(cfg.Lead).Unix()
	res.Timestamp = timestamp
	reg, err := c.registerIdentity(ctx, timestamp, prefix)
	if err != nil {
		res.Stage, res.Err = StageRegister, err
		return res
	}
	res.TxHash = reg.TxHash
	if reg.Identity != data.Identity {
		res.Stage, res.Err = StageRegister, fmt.Errorf("registered identity %s does not match %s", reg.Identity, data.Identity)
		return res
	}

	// 4. Sleep until the timestamp before polling at all. Polling earlier only
	//    produces "timestamp not reached yet" and burns rate limit — at one round
	//    per minute over a day that difference is thousands of requests.
	deadline := time.Unix(timestamp, 0)
	if wait := time.Until(deadline); wait > 0 {
		select {
		case <-ctx.Done():
			res.Stage, res.Err = StagePoll, ctx.Err()
			return res
		case <-time.After(wait):
		}
	}

	// 5. Poll until the key appears or we give up.
	key, lastPoll, err := poll(ctx, c, cfg, data.Identity, deadline)
	res.LastPoll = lastPoll
	if err != nil {
		res.Stage, res.Err = StagePoll, err
		return res
	}
	res.Latency = time.Since(deadline)

	// 6. Decrypt and check we got our own plaintext back.
	decrypted, err := decryptWith(encrypted, key.DecryptionKey)
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

// poll asks for the decryption key until it arrives or PollTimeout elapses past
// the decryption timestamp. The returned string is the API's last non-200
// description, which distinguishes "registration never landed" from "no key".
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