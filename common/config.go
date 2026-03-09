package common

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"

	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
)

type Config struct {
	KeyperHTTPURL   *url.URL
	SigningKey      *ecdsa.PrivateKey
	PublicKey       *ecdsa.PublicKey
	P2P             *p2p.Config
	DisableEventAPI bool // true when SHUTTER_EVENT_REGISTRY_CONTRACT_ADDRESS is not configured; if true, event API endpoints are not registered
}

func NewConfig(keyperHTTPUrl string, signingKey *ecdsa.PrivateKey, p2pConfig *p2p.Config) (*Config, error) {
	parsedURL, err := url.Parse(keyperHTTPUrl)
	if err != nil {
		return nil, err
	}
	publicKey, ok := signingKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot create public key")
	}
	return &Config{
		KeyperHTTPURL: parsedURL,
		SigningKey:    signingKey,
		PublicKey:     publicKey,
		P2P:           p2pConfig,
	}, nil
}
