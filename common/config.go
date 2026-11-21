package common

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"strings"

	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
)

type Config struct {
	// KeyperHTTPURLs are the keyper http apis asked, in this order, for a
	// decryption key that is not in the database yet.
	KeyperHTTPURLs  []*url.URL
	SigningKey      *ecdsa.PrivateKey
	PublicKey       *ecdsa.PublicKey
	P2P             *p2p.Config
	DisableEventAPI bool // true when SHUTTER_EVENT_REGISTRY_CONTRACT_ADDRESS is not configured; if true, event API endpoints are not registered
}

func NewConfig(keyperHTTPUrl string, signingKey *ecdsa.PrivateKey, p2pConfig *p2p.Config) (*Config, error) {
	keyperHTTPURLs, err := ParseKeyperHTTPURLs(keyperHTTPUrl)
	if err != nil {
		return nil, err
	}
	publicKey, ok := signingKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot create public key")
	}
	return &Config{
		KeyperHTTPURLs: keyperHTTPURLs,
		SigningKey:     signingKey,
		PublicKey:      publicKey,
		P2P:            p2pConfig,
	}, nil
}

// ParseKeyperHTTPURLs parses KEYPER_HTTP_URL, which holds one keyper url or
// several separated by commas, the same way P2P_BOOTSTRAP_ADDRESSES is given.
// White space around an entry and empty entries, such as one left by a
// trailing comma, are ignored. A value with no entry at all is parsed as a
// single url, as it was before lists were accepted, so an unset variable still
// starts the api and the fallback fails at request time as it did then.
func ParseKeyperHTTPURLs(value string) ([]*url.URL, error) {
	var urls []*url.URL
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parsedURL, err := url.Parse(entry)
		if err != nil {
			return nil, err
		}
		urls = append(urls, parsedURL)
	}
	if len(urls) == 0 {
		parsedURL, err := url.Parse(value)
		if err != nil {
			return nil, err
		}
		urls = append(urls, parsedURL)
	}
	return urls, nil
}
