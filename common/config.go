package common

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
)

type Config struct {
	KeyperHTTPURL                *url.URL
	SigningKey                   *ecdsa.PrivateKey
	PublicKey                    *ecdsa.PublicKey
	P2P                          *p2p.Config
	WhitelistedContractAddresses []common.Address
}

func NewConfig(keyperHTTPUrl string, signingKey *ecdsa.PrivateKey, p2pConfig *p2p.Config, whitelistedContractAddresses []common.Address) (*Config, error) {
	parsedURL, err := url.Parse(keyperHTTPUrl)
	if err != nil {
		return nil, err
	}
	publicKey, ok := signingKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot create public key")
	}
	return &Config{
		KeyperHTTPURL:                parsedURL,
		SigningKey:                   signingKey,
		PublicKey:                    publicKey,
		P2P:                          p2pConfig,
		WhitelistedContractAddresses: whitelistedContractAddresses,
	}, nil
}
