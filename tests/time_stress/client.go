package time_stress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type client struct {
	baseURL string
	auth    string
	http    *http.Client
}

func newClient(cfg Config) *client {
	// A tuned transport: the default http.DefaultTransport caps connections per
	// host at 2, which cripples any run with WORKERS > 2 by serialising them on
	// the connection pool. Here we match MaxIdleConnsPerHost to the worker count
	// (with a floor) so concurrent requests actually run concurrently.
	//
	// This is why running with WORKERS=50 and the default transport would appear
	// as if the API couldn't keep up when the real limit was the client.
	maxConns := cfg.Workers
	if maxConns < 32 {
		maxConns = 32
	}
	tr := &http.Transport{
		MaxIdleConns:        maxConns * 2,
		MaxIdleConnsPerHost: maxConns,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
	return &client{
		baseURL: cfg.APIBaseURL,
		auth:    cfg.AuthToken,
		http: &http.Client{
			Timeout:   cfg.HTTPTimeout,
			Transport: tr,
		},
	}
}

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
