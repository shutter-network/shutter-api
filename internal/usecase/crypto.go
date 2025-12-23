package usecase

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	cryptorand "crypto/rand"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/data"
	httpError "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/metrics"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

const IdentityPrefixByteLength = 32

type ShutterregistryInterface interface {
	Registrations(opts *bind.CallOpts, identity [32]byte) (
		struct {
			Eon       uint64
			Timestamp uint64
		},
		error,
	)
	Register(opts *bind.TransactOpts, eon uint64, identityPrefix [32]byte, timestamp uint64) (*types.Transaction, error)
}

type ShutterEventregistryInterface interface {
	Register(opts *bind.TransactOpts, eon uint64, identityPrefix [32]byte, triggerDefinition []byte, ttl uint64) (*types.Transaction, error)
}

type KeyperSetManagerInterface interface {
	GetKeyperSetIndexByBlock(opts *bind.CallOpts, blockNumber uint64) (uint64, error)
}

type KeyBroadcastInterface interface {
	GetEonKey(opts *bind.CallOpts, eon uint64) ([]byte, error)
}

type EthClientInterface interface {
	BlockNumber(ctx context.Context) (uint64, error)
	ChainID(ctx context.Context) (*big.Int, error)
}

type GetDecryptionKeyResponse struct {
	DecryptionKey       string `json:"decryption_key" example:"0x99a805fc26812c13041126b25e91eccf3de464d1df7a95d1edca8831a9ec02dd"`
	Identity            string `json:"identity" example:"0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"`
	DecryptionTimestamp uint64 `json:"decryption_timestamp" example:"1735044061"`
} // @name GetDecryptionKey

type GetDataForEncryptionResponse struct {
	Eon            uint64 `json:"eon" example:"1"`
	Identity       string `json:"identity" example:"0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"`
	IdentityPrefix string `json:"identity_prefix" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
	EonKey         string `json:"eon_key" example:"0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255"`
	EpochID        string `json:"epoch_id" example:"0x88f2495d1240f9c5523db589996a50a4984ee7a08a8a8f4b269e4345b383310abd2dc1cd9c9c2b8718ed3f486d5242f5"`
} // @name GetDataForEncryption

type RegisterIdentityResponse struct {
	Eon            uint64 `json:"eon" example:"1"`
	Identity       string `json:"identity" example:"0x8c232eae4f957259e9d6b68301d529e9851b8642874c8f59d2bd0fb84a570c75"`
	IdentityPrefix string `json:"identity_prefix" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
	EonKey         string `json:"eon_key" example:"0x57af5437a84ef50e5ed75772c18ae38b168bb07c50cadb65fc6136604e662255"`
	TxHash         string `json:"tx_hash" example:"0x3026ad202ca611551377eef069fb6ed894eae65329ce73c56f300129694f12ba"`
} // @name RegisterIdentityResponse

type CryptoUsecase struct {
	db                           *pgxpool.Pool
	dbQuery                      *data.Queries
	shutterRegistryContract      ShutterregistryInterface
	shutterEventRegistryContract ShutterEventregistryInterface
	keyperSetManagerContract     KeyperSetManagerInterface
	keyBroadcastContract         KeyBroadcastInterface
	ethClient                    EthClientInterface
	config                       *common.Config
}

func NewCryptoUsecase(
	db *pgxpool.Pool,
	shutterRegistryContract ShutterregistryInterface,
	shutterEventRegistryContract ShutterEventregistryInterface,
	keyperSetManagerContract KeyperSetManagerInterface,
	keyBroadcastContract KeyBroadcastInterface,
	ethClient EthClientInterface,
	config *common.Config,
) *CryptoUsecase {
	return &CryptoUsecase{
		db:                           db,
		dbQuery:                      data.New(db),
		shutterRegistryContract:      shutterRegistryContract,
		shutterEventRegistryContract: shutterEventRegistryContract,
		keyperSetManagerContract:     keyperSetManagerContract,
		keyBroadcastContract:         keyBroadcastContract,
		ethClient:                    ethClient,
		config:                       config,
	}
}

func (uc *CryptoUsecase) GetDecryptionKey(ctx context.Context, identity string) (*GetDecryptionKeyResponse, *httpError.Http) {
	identityBytes, err := hex.DecodeString(strings.TrimPrefix(string(identity), "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding identity")
		err := httpError.NewHttpError(
			"error encountered while decoding identity",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	if len(identityBytes) != 32 {
		log.Err(err).Msg("identity should be of length 32")
		err := httpError.NewHttpError(
			"identity should be of length 32",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	registrationData, err := uc.shutterRegistryContract.Registrations(nil, [32]byte(identityBytes))
	if err != nil {
		log.Err(err).Msg("err encountered while querying contract")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error while querying for identity from the contract",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	if registrationData.Timestamp == 0 {
		log.Err(err).Msg("identity not registered")
		err := httpError.NewHttpError(
			"identity has not been registerd yet",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	currentTimestamp := time.Now().Unix()
	if currentTimestamp < int64(registrationData.Timestamp) {
		log.Debug().Uint64("decryptionTimestamp", registrationData.Timestamp).Int64("currentTimestamp", currentTimestamp).Msg("timestamp not reached yet, decryption key requested too early")
		err := httpError.NewHttpError(
			"timestamp not reached yet, decryption key requested too early",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	var decryptionKey string

	decKey, err := uc.dbQuery.GetDecryptionKey(ctx, data.GetDecryptionKeyParams{
		Eon:     int64(registrationData.Eon),
		EpochID: identityBytes,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			// no data found try querying from other keyper via http
			decKey, err := uc.getDecryptionKeyFromExternalKeyper(ctx, int64(registrationData.Eon), identity)
			if err != nil {
				err := httpError.NewHttpError(
					err.Error(),
					"",
					http.StatusInternalServerError,
				)
				return nil, &err
			}
			if decKey == "" {
				err := httpError.NewHttpError(
					"decryption key doesnt exist",
					"",
					http.StatusNotFound,
				)
				return nil, &err
			}
			decryptionKey = decKey
		} else {
			log.Err(err).Msg("err encountered while querying db")
			err := httpError.NewHttpError(
				"error while querying db",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
	} else {
		decryptionKey = common.PrefixWith0x(hex.EncodeToString(decKey.DecryptionKey))
	}

	if !strings.HasPrefix(identity, "0x") {
		identity = common.PrefixWith0x(identity)
	}

	return &GetDecryptionKeyResponse{
		DecryptionKey:       decryptionKey,
		Identity:            identity,
		DecryptionTimestamp: registrationData.Timestamp,
	}, nil
}

func (uc *CryptoUsecase) GetDataForEncryption(ctx context.Context, address string, identityPrefixStringified string) (*GetDataForEncryptionResponse, *httpError.Http) {
	if !ethCommon.IsHexAddress(address) {
		log.Warn().Str("address", address).Msg("invalid address")
		err := httpError.NewHttpError(
			"invalid address",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}
	var identityPrefix shcrypto.Block

	if len(identityPrefixStringified) > 0 {
		trimmedIdentityPrefix := strings.TrimPrefix(identityPrefixStringified, "0x")
		if len(trimmedIdentityPrefix) != 2*IdentityPrefixByteLength {
			log.Warn().Msg("identity prefix should be of byte length 32")
			err := httpError.NewHttpError(
				"identity prefix should be of byte length 32",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefixBytes, err := hex.DecodeString(trimmedIdentityPrefix)
		if err != nil {
			log.Err(err).Msg("err encountered while decoding identity prefix")
			err := httpError.NewHttpError(
				"error encountered while decoding identity prefix",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefix = shcrypto.Block(identityPrefixBytes)
	} else {
		// generate a random one
		block, err := shcrypto.RandomSigma(cryptorand.Reader)
		if err != nil {
			log.Err(err).Msg("err encountered while generating identity prefix")
			err := httpError.NewHttpError(
				"error encountered while generating identity prefix",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
		identityPrefix = block
	}

	blockNumber, err := uc.ethClient.BlockNumber(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for recent block")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for recent block",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eon, err := uc.keyperSetManagerContract.GetKeyperSetIndexByBlock(nil, blockNumber)
	if err != nil {
		log.Err(err).Msg("err encountered while querying keyper set index")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for keyper set index",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKeyBytes, err := uc.keyBroadcastContract.GetEonKey(nil, eon)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for eon key")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKey := &shcrypto.EonPublicKey{}
	if err := eonKey.Unmarshal(eonKeyBytes); err != nil {
		log.Err(err).Msg("err encountered while deserializing eon key")
		err := httpError.NewHttpError(
			"error encountered while querying deserializing eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	identity := common.ComputeIdentity(identityPrefix[:], ethCommon.HexToAddress(address))
	epochID := shcrypto.ComputeEpochID(identity)
	return &GetDataForEncryptionResponse{
		Eon:            eon,
		Identity:       common.PrefixWith0x(hex.EncodeToString(identity)),
		IdentityPrefix: common.PrefixWith0x(hex.EncodeToString(identityPrefix[:])),
		EonKey:         common.PrefixWith0x(hex.EncodeToString(eonKeyBytes)),
		EpochID:        common.PrefixWith0x(hex.EncodeToString(epochID.Marshal())),
	}, nil
}

func (uc *CryptoUsecase) RegisterIdentity(ctx context.Context, decryptionTimestamp uint64, identityPrefixStringified string) (*RegisterIdentityResponse, *httpError.Http) {
	currentTimestamp := time.Now().Unix()
	if currentTimestamp > int64(decryptionTimestamp) {
		log.Debug().Uint64("decryptionTimestamp", decryptionTimestamp).Int64("currentTimestamp", currentTimestamp).Msg("decryption timestamp should be in future")
		err := httpError.NewHttpError(
			"decryption timestamp should be in future",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}
	var identityPrefix shcrypto.Block

	if len(identityPrefixStringified) > 0 {
		trimmedIdentityPrefix := strings.TrimPrefix(identityPrefixStringified, "0x")
		if len(trimmedIdentityPrefix) != 2*IdentityPrefixByteLength {
			log.Warn().Msg("identity prefix should be of byte length 32")
			err := httpError.NewHttpError(
				"identity prefix should be of byte length 32",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefixBytes, err := hex.DecodeString(trimmedIdentityPrefix)
		if err != nil {
			log.Err(err).Msg("err encountered while decoding identity prefix")
			err := httpError.NewHttpError(
				"error encountered while decoding identity prefix",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefix = shcrypto.Block(identityPrefixBytes)
	} else {
		// generate a random one
		block, err := shcrypto.RandomSigma(cryptorand.Reader)
		if err != nil {
			log.Err(err).Msg("err encountered while generating identity prefix")
			err := httpError.NewHttpError(
				"error encountered while generating identity prefix",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
		identityPrefix = block
	}

	blockNumber, err := uc.ethClient.BlockNumber(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for recent block")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for recent block",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eon, err := uc.keyperSetManagerContract.GetKeyperSetIndexByBlock(nil, blockNumber)
	if err != nil {
		log.Err(err).Msg("err encountered while querying keyper set index")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for keyper set index",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKeyBytes, err := uc.keyBroadcastContract.GetEonKey(nil, eon)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for eon key")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying for eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKey := &shcrypto.EonPublicKey{}
	if err := eonKey.Unmarshal(eonKeyBytes); err != nil {
		log.Err(err).Msg("err encountered while deserializing eon key")
		err := httpError.NewHttpError(
			"error encountered while querying deserializing eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	chainId, err := uc.ethClient.ChainID(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while quering chain id")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error encountered while querying chain id",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	newSigner, err := bind.NewKeyedTransactorWithChainID(uc.config.SigningKey, chainId)
	if err != nil {
		log.Err(err).Msg("err encountered while creating signer")
		err := httpError.NewHttpError(
			"error encountered while registering identity",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	identity := common.ComputeIdentity(identityPrefix[:], newSigner.From)

	// TODO: check for already registered identities also against event based triggers!
	registrationData, err := uc.shutterRegistryContract.Registrations(nil, [32]byte(identity))
	if err != nil {
		log.Err(err).Msg("err encountered while querying contract")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"error while querying for registrations from the contract",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	if registrationData.Timestamp > 0 {
		log.Err(err).Msg("identity already registered")
		err := httpError.NewHttpError(
			"identity already registered",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	publicAddress := crypto.PubkeyToAddress(*uc.config.PublicKey)

	opts := bind.TransactOpts{
		From:   publicAddress,
		Signer: newSigner.Signer,
	}

	tx, err := uc.shutterRegistryContract.Register(&opts, eon, identityPrefix, decryptionTimestamp)
	if err != nil {
		log.Err(err).Msg("failed to send transaction")
		metrics.TotalFailedRPCCalls.Inc()
		err := httpError.NewHttpError(
			"failed to register identity",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}
	// not launching a routine to monitor the transaction
	// we return the transaction hash in response to allow
	// users the ability to monitor it themselves

	metrics.TotalSuccessfulIdentityRegistration.Inc()
	return &RegisterIdentityResponse{
		Eon:            eon,
		Identity:       common.PrefixWith0x(hex.EncodeToString(identity)),
		IdentityPrefix: common.PrefixWith0x(hex.EncodeToString(identityPrefix[:])),
		EonKey:         common.PrefixWith0x(hex.EncodeToString(eonKeyBytes)),
		TxHash:         tx.Hash().Hex(),
	}, nil
}

func (uc *CryptoUsecase) DecryptCommitment(ctx context.Context, encryptedCommitment string, identity string) (string, *httpError.Http) {
	if len(encryptedCommitment) == 0 {
		log.Debug().Msg("empty encrypted commitment")
		err := httpError.NewHttpError(
			"empty encrypted commitment",
			"",
			http.StatusBadRequest,
		)
		return "", &err
	}
	encryptedCommitmentBytes, err := hex.DecodeString(strings.TrimPrefix(encryptedCommitment, "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding encrypted commitment")
		err := httpError.NewHttpError(
			"error encountered while decoding encrypted commitment",
			"",
			http.StatusBadRequest,
		)
		return "", &err
	}

	decKeyResponse, httpErr := uc.GetDecryptionKey(ctx, identity)
	if httpErr != nil {
		return "", httpErr
	}

	key, err := hex.DecodeString(strings.TrimPrefix(decKeyResponse.DecryptionKey, "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding decryption key")
		err := httpError.NewHttpError(
			"error encountered while decoding decryption key",
			"",
			http.StatusInternalServerError,
		)
		return "", &err
	}

	decryptionKey := new(shcrypto.EpochSecretKey)
	err = decryptionKey.Unmarshal(key)
	if err != nil {
		log.Err(err).Msg("err while decoding decryption key")
		err := httpError.NewHttpError(
			"error while decoding decryption key",
			"",
			http.StatusInternalServerError,
		)
		return "", &err
	}

	encryptedMsg := new(shcrypto.EncryptedMessage)
	err = encryptedMsg.Unmarshal(encryptedCommitmentBytes)
	if err != nil {
		log.Err(err).Msg("err while decoding encrypted commitment")
		err := httpError.NewHttpError(
			"error while decoding encrypted commitment",
			"",
			http.StatusBadRequest,
		)
		return "", &err
	}

	decryptedMsg, err := encryptedMsg.Decrypt(decryptionKey)
	if err != nil {
		log.Err(err).Msg("err while decrypting message")
		err := httpError.NewHttpError(
			"error encountered while decrypting message",
			"",
			http.StatusInternalServerError,
		)
		return "", &err
	}

	return common.PrefixWith0x(hex.EncodeToString(decryptedMsg)), nil
}

func (uc *CryptoUsecase) getDecryptionKeyFromExternalKeyper(ctx context.Context, eon int64, identity string) (string, error) {
	path := uc.config.KeyperHTTPURL.JoinPath("/decryptionKey/", fmt.Sprint(eon), "/", identity)

	req, err := http.NewRequestWithContext(ctx, "GET", path.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get decryption key for eon %d and identity %s from keyper", eon, identity)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if res.StatusCode != http.StatusOK {
		return "", errors.Wrapf(err, "failed to get decryption key for eon %d and identity %s from keyper", eon, identity)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read keypers response body")
	}

	decryptionKey := string(body)

	return decryptionKey, nil
}
