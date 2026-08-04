package continuous

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// client wraps the three time-based endpoints the monitor needs. It deliberately
// speaks only the public HTTP contract.
type client struct {
	baseURL string
	auth    string
	http    *http.Client
}

func newClient(cfg Config) *client {
	return &client{
		baseURL: cfg.APIBaseURL,
		auth:    cfg.AuthToken,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// apiError is the API's error envelope, e.g.
// {"description":"identity has not been registerd yet","statusCode":400}
type apiError struct {
	Description string `json:"description"`
	StatusCode  int    `json:"statusCode"`
}

type dataForEncryption struct {
	Eon            uint64 `json:"eon"`
	Identity       string `json:"identity"`
	IdentityPrefix string `json:"identity_prefix"`
	EonKey         string `json:"eon_key"`
	EpochID        string `json:"epoch_id"`
}

type registration struct {
	Eon            uint64 `json:"eon"`
	Identity       string `json:"identity"`
	IdentityPrefix string `json:"identity_prefix"`
	EonKey         string `json:"eon_key"`
	TxHash         string `json:"tx_hash"`
}

type decryptionKey struct {
	DecryptionKey       string `json:"decryption_key"`
	Identity            string `json:"identity"`
	DecryptionTimestamp uint64 `json:"decryption_timestamp"`
}

// do performs the request and returns the status code and body. A non-2xx status
// is not an error here: the poll loop needs to inspect 400s and 404s to tell
// "not yet" from "never landed".
func (c *client) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.auth != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// describe turns a non-2xx body into the API's description string, falling back to
// the raw body when it isn't the expected envelope.
func describe(status int, raw []byte) string {
	var e apiError
	if err := json.Unmarshal(raw, &e); err == nil && e.Description != "" {
		return fmt.Sprintf("http=%d %s", status, e.Description)
	}
	return fmt.Sprintf("http=%d %s", status, bytes.TrimSpace(raw))
}

func unwrap[T any](raw []byte) (T, error) {
	var envelope struct {
		Message T `json:"message"`
	}
	err := json.Unmarshal(raw, &envelope)
	return envelope.Message, err
}

func (c *client) getDataForEncryption(ctx context.Context, addr, prefix string) (dataForEncryption, error) {
	path := fmt.Sprintf("/api/time/get_data_for_encryption?address=%s&identityPrefix=%s", addr, prefix)
	status, raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return dataForEncryption{}, err
	}
	if status != http.StatusOK {
		return dataForEncryption{}, fmt.Errorf("get_data_for_encryption: %s", describe(status, raw))
	}
	return unwrap[dataForEncryption](raw)
}

func (c *client) registerIdentity(ctx context.Context, timestamp int64, prefix string) (registration, error) {
	body, err := json.Marshal(map[string]any{
		"decryptionTimestamp": timestamp,
		"identityPrefix":      prefix,
	})
	if err != nil {
		return registration{}, err
	}
	status, raw, err := c.do(ctx, http.MethodPost, "/api/time/register_identity", body)
	if err != nil {
		return registration{}, err
	}
	if status != http.StatusOK {
		return registration{}, fmt.Errorf("register_identity: %s", describe(status, raw))
	}
	return unwrap[registration](raw)
}

// getDecryptionKey returns the key on success. On a non-200 it returns the
// description so the caller can log why it is still waiting, with a nil error —
// only transport failures are errors.
func (c *client) getDecryptionKey(ctx context.Context, identity string) (decryptionKey, string, error) {
	path := "/api/time/get_decryption_key?identity=" + identity
	status, raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return decryptionKey{}, "", err
	}
	if status != http.StatusOK {
		return decryptionKey{}, describe(status, raw), nil
	}
	key, err := unwrap[decryptionKey](raw)
	return key, "", err
}