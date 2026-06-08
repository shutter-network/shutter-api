package eventsmoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func compileTrigger(cfg *Config, event string, args []EventArg) (string, error) {
	req := compileReq{
		Contract: cfg.PlaygroundAddr,
		EventSig: event,
		Args:     args,
	}

	var payload map[string]any
	if err := postJSON(cfg, "/event/compile_trigger_definition", req, &payload); err != nil {
		return "", err
	}

	if v := str(payload["trigger_definition"]); v != "" {
		return v, nil
	}
	if v := str(payload["triggerDefinition"]); v != "" {
		return v, nil
	}
	if msgObj, ok := payload["message"].(map[string]any); ok {
		if v := str(msgObj["trigger_definition"]); v != "" {
			return v, nil
		}
		if v := str(msgObj["triggerDefinition"]); v != "" {
			return v, nil
		}
	}

	return "", errors.New(extractErr(payload))
}

func registerIdentity(cfg *Config, triggerDef string) (identity string, eon int64, txHash string, prefix string, err error) {
	randHex, err := runCmd("openssl", "rand", "-hex", "32")
	if err != nil {
		return "", 0, "", "", err
	}
	prefix = "0x" + strings.TrimSpace(randHex)

	req := registerReq{
		TriggerDefinition: triggerDef,
		IdentityPrefix:    prefix,
		TTL:               cfg.TTL,
	}

	var payload map[string]any
	if err := postJSON(cfg, "/event/register_identity", req, &payload); err != nil {
		return "", 0, "", "", err
	}

	root := payload
	if m, ok := payload["message"].(map[string]any); ok {
		root = m
	}

	identity = str(root["identity"])
	txHash = str(root["tx_hash"])
	eon = toInt64(root["eon"])

	if identity == "" || txHash == "" || eon == 0 {
		return "", 0, "", "", errors.New(extractErr(payload))
	}
	return
}

func getDecryptionKey(cfg *Config, identity string, eon int64) (key, msg string, ok bool) {
	u, _ := url.Parse(cfg.APIBase + "/event/get_decryption_key")
	q := u.Query()
	q.Set("identity", identity)
	q.Set("eon", fmt.Sprint(eon))
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	applyAuthHeader(req, cfg.AuthHeader)

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return "", "api timeout (keyper fallback likely hanging)", false
		}
		return "", err.Error(), false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	raw := strings.TrimSpace(string(body))
	logf(cfg, "GET %s status=%d body=%s", u.String(), resp.StatusCode, raw)

	if strings.HasPrefix(raw, "0x") && len(raw) > 2 {
		return raw, "", true
	}

	var m map[string]any
	_ = json.Unmarshal(body, &m)

	if v := str(m["decryption_key"]); strings.HasPrefix(v, "0x") && len(v) > 2 {
		return v, "", true
	}
	if msgObj, ok := m["message"].(map[string]any); ok {
		if v := str(msgObj["decryption_key"]); strings.HasPrefix(v, "0x") && len(v) > 2 {
			return v, "", true
		}
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Sprintf("http %d: %s", resp.StatusCode, raw), false
	}

	e := extractErr(m)
	if e == "unknown error" && raw != "" {
		e = raw
	}
	return "", e, false
}

func postJSON(cfg *Config, path string, body any, out any) error {
	reqBytes, _ := json.Marshal(body)
	fullURL := cfg.APIBase + path

	req, _ := http.NewRequest(http.MethodPost, fullURL, bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/json")
	applyAuthHeader(req, cfg.AuthHeader)

	logf(cfg, "POST %s body=%s", fullURL, string(reqBytes))
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	logf(cfg, "POST %s status=%d body=%s", fullURL, resp.StatusCode, strings.TrimSpace(string(respBytes)))

	_ = json.Unmarshal(respBytes, out)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return nil
}

func applyAuthHeader(req *http.Request, authHeader string) {
	if strings.TrimSpace(authHeader) == "" {
		return
	}
	p := strings.SplitN(authHeader, ":", 2)
	if len(p) != 2 {
		return
	}
	req.Header.Set(strings.TrimSpace(p[0]), strings.TrimSpace(p[1]))
}

func extractErr(m map[string]any) string {
	if s := str(m["description"]); s != "" {
		return s
	}
	if s := str(m["error"]); s != "" {
		return s
	}
	if s := str(m["message"]); s != "" {
		return s
	}
	if errs, ok := m["errors"].([]any); ok && len(errs) > 0 {
		return fmt.Sprint(errs[0])
	}
	return "unknown error"
}