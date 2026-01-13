package usecase

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/data"
	httpError "github.com/shutter-network/shutter-api/internal/error"
	sherror "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/metrics"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

type EventArgument struct {
	Name     string `json:"name" example:"amount"`
	Operator string `json:"op" example:"gte"`
	Number   int    `json:"number" example:"25433"`
	Bytes    string `json:"bytes" example:"0xabcdef01234567"`
}
type EventTriggerDefinitionRequest struct {
	EventSignature  string          `json:"eventSig" example:"Transfer(address indexed from, address indexed to, uint256 amount)"`
	ContractAddress ecommon.Address `json:"contract" swaggertype:"string" example:"0x3465a347342B72BCf800aBf814324ba4a803c32b"`
	Arguments       []EventArgument `json:"arguments"`
} // @name EventTriggerDefinitionRequest

type EventTriggerDefinitionResponse struct {
	EventTriggerDefinition string `json:"trigger_definition" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
}

type GetEventTriggerExpirationBlockResponse struct {
	ExpirationBlockNumber uint64 `json:"expiration_block_number" example:"12345678"`
} // @name GetEventTriggerExpirationBlock

func CompileEventTriggerDefinitionInternal(req EventTriggerDefinitionRequest) (EventTriggerDefinitionResponse, []error) {
	var errors []error
	zeroAddress := ecommon.Address{}
	if req.ContractAddress == zeroAddress {
		err := fmt.Errorf("Contract address empty")
		log.Err(err).Msg("error creating event trigger definition")
		err = sherror.NewHttpError(
			"unable to parse event trigger definition",
			err.Error(),
			http.StatusBadRequest,
		)
		errors = append(errors, err)
	}
	if len(req.EventSignature) == 0 {
		err := fmt.Errorf("No event signature given")
		log.Err(err).Msg("error creating event trigger definition")
		err = sherror.NewHttpError(
			"unable to parse event trigger definition",
			err.Error(),
			http.StatusBadRequest,
		)
		errors = append(errors, err)
	}
	predicates, err := logPredicates(req.Arguments, req.EventSignature)
	if err != nil {
		log.Err(err).Msg("error parsing event trigger definition")
		err := sherror.NewHttpError(
			"unable to parse event trigger definition",
			err.Error(),
			http.StatusBadRequest,
		)
		errors = append(errors, err)
	}
	etd := shs.EventTriggerDefinition{
		Contract:      req.ContractAddress,
		LogPredicates: predicates,
	}
	err = etd.Validate()
	if err != nil {
		log.Err(err).Msg("error validating event trigger definition")
		err := sherror.NewHttpError(
			"event trigger definition invalid",
			err.Error(),
			http.StatusBadRequest,
		)
		errors = append(errors, err)
	}

	data := EventTriggerDefinitionResponse{EventTriggerDefinition: common.PrefixWith0x(hex.EncodeToString(etd.MarshalBytes()))}
	return data, errors
}

// aligns []byte to 32 byte
func Align(val []byte) []byte {
	words := (31 + len(val)) / shs.Word
	x := make([]byte, shs.Word*words)
	copy(x[len(x)-len(val):], val)
	return x
}

func Topic0(sig sigparser.Signature) shs.LogPredicate {
	var b strings.Builder
	b.WriteString(sig.Name)
	b.WriteString("(")
	for i, input := range sig.Inputs {
		b.WriteString(input.Type)
		if i < len(sig.Inputs)-1 {
			b.WriteString(",")
		}
	}
	b.WriteString(")")
	lp := shs.LogPredicate{}
	lp.LogValueRef.Length = 1
	lp.LogValueRef.Offset = 0
	h := crypto.Keccak256([]byte(b.String()))
	lp.ValuePredicate.ByteArgs = [][]byte{h}
	lp.ValuePredicate.Op = shs.BytesEq
	return lp
}

func logPredicates(args []EventArgument, evtSig string) ([]shs.LogPredicate, error) {
	lps := []shs.LogPredicate{}
	sig, err := sigparser.ParseSignature(evtSig)
	if err != nil {
		return lps, err
	}
	lp := Topic0(sig)
	lps = append(lps, lp)
	indexedOffset := uint64(1)
	nonIndexedOffset := uint64(4)
	length := uint64(0)
	argnames := make([]string, len(args))
	for i, arg := range args {
		found := slices.IndexFunc(
			sig.Inputs,
			func(par sigparser.Parameter) bool {
				return par.Name == arg.Name
			})
		if found < 0 {
			return lps, fmt.Errorf("argument '%v' not defined in signature", arg.Name)
		}
		double := slices.IndexFunc(
			argnames,
			func(name string) bool {
				return name == arg.Name
			})
		if double >= 0 {
			return lps, fmt.Errorf("argument '%v' was defined more than once", arg.Name)
		}
		argnames[i] = arg.Name
	}
	for _, input := range sig.Inputs {
		lp := shs.LogPredicate{}
		i := slices.IndexFunc(
			args,
			func(ea EventArgument) bool {
				return ea.Name == input.Name
			})
		// input is part of definition:
		if i >= 0 {
			arg := args[i]
			// input is topic:
			if input.Indexed {
				val, err := hexutil.Decode(arg.Bytes)
				if err != nil {
					return lps, err
				}
				length = 1
				if arg.Operator != "eq" {
					return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
				}
				lp.ValuePredicate.Op = shs.BytesEq
				lp.ValuePredicate.ByteArgs = [][]byte{Align(val)}
				lp.LogValueRef.Offset = indexedOffset
				indexedOffset++
				// input is data argument:
			} else {
				if input.Type != "uint256" {
					val, err := hexutil.Decode(arg.Bytes)
					if err != nil {
						return lps, err
					}
					if arg.Operator != "eq" {
						return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
					}
					lp.ValuePredicate.Op = shs.BytesEq
					lp.ValuePredicate.ByteArgs = [][]byte{Align(val)}
					length = uint64(len(val) / shs.Word)
				} else {
					lp.ValuePredicate.Op = opFromString(arg.Operator)
					lp.ValuePredicate.IntArgs = []*big.Int{big.NewInt(int64(arg.Number))}
					length = 1
				}

				lp.LogValueRef.Offset = nonIndexedOffset
				nonIndexedOffset += length
			}
			lp.LogValueRef.Length = length
			lps = append(lps, lp)
		}
	}
	return lps, nil
}

func opFromString(op string) shs.Op {
	switch strings.ToLower(op) {
	case "lt":
		return shs.UintLt
	case "lte":
		return shs.UintLte
	case "eq":
		return shs.UintEq
	case "gt":
		return shs.UintGt
	case "gte":
		return shs.UintGte
	default:
		return shs.BytesEq
	}
}

func (uc *CryptoUsecase) RegisterEventIdentity(ctx context.Context, eventTriggerDefinitionHex string, identityPrefixStringified string, ttl uint64) (*RegisterIdentityResponse, *httpError.Http) {
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

	eventTriggerDefinition, err := hexutil.Decode(eventTriggerDefinitionHex)
	if err != nil {
		err := httpError.NewHttpError(
			"could not decode event trigger definition",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	etd := shs.EventTriggerDefinition{}
	if err := etd.UnmarshalBytes(eventTriggerDefinition); err != nil {
		log.Err(err).Msg("err encountered while unmarshaling event trigger definition")
		err := httpError.NewHttpError(
			"could not parse event trigger definition",
			"",
			http.StatusBadRequest,
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

	identity := common.ComputeEventIdentity(identityPrefix[:], newSigner.From, eventTriggerDefinition)

	_, err = uc.dbQuery.GetEventIdentityRegistration(ctx, data.GetEventIdentityRegistrationParams{
		Eon:            int64(eon),
		IdentityPrefix: identityPrefix[:],
		Sender:         newSigner.From.Hex(),
	})
	if err == nil {
		log.Warn().Msg("event identity already registered")
		err := httpError.NewHttpError(
			"event identity already registered",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	} else if err != pgx.ErrNoRows {
		// Unexpected database error
		log.Err(err).Msg("err encountered while querying event identity registration")
		err := httpError.NewHttpError(
			"error encountered while checking event identity registration",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	publicAddress := crypto.PubkeyToAddress(*uc.config.PublicKey)

	opts := bind.TransactOpts{
		From:   publicAddress,
		Signer: newSigner.Signer,
	}

	tx, err := uc.shutterEventRegistryContract.Register(&opts, eon, identityPrefix, eventTriggerDefinition, ttl)
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

	// Store the registration in database
	txHashBytes := tx.Hash().Bytes()
	err = uc.dbQuery.InsertEventIdentityRegistration(ctx, data.InsertEventIdentityRegistrationParams{
		Eon:                    int64(eon),
		Identity:               identity,
		IdentityPrefix:         identityPrefix[:],
		Sender:                 newSigner.From.Hex(),
		EventTriggerDefinition: eventTriggerDefinition,
		TxHash:                 txHashBytes,
	})
	if err != nil {
		log.Err(err).Msg("err encountered while storing event identity registration")
		// Note: Transaction already sent, so we log the error but don't fail the request
		// The registration is on-chain even if DB insert fails
	}

	go uc.updateEventIdentityExpirationBlockNumber(tx.Hash(), eon, identityPrefix[:], newSigner.From.Hex(), ttl)

	metrics.TotalSuccessfulIdentityRegistration.Inc()
	return &RegisterIdentityResponse{
		Eon:            eon,
		Identity:       common.PrefixWith0x(hex.EncodeToString(identity)),
		IdentityPrefix: common.PrefixWith0x(hex.EncodeToString(identityPrefix[:])),
		EonKey:         common.PrefixWith0x(hex.EncodeToString(eonKeyBytes)),
		TxHash:         tx.Hash().Hex(),
	}, nil
}

func (uc *CryptoUsecase) updateEventIdentityExpirationBlockNumber(txHash ecommon.Hash, eon uint64, identityPrefix []byte, sender string, ttl uint64) {
	ctx := context.Background()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		receipt, err := uc.ethClient.TransactionReceipt(ctx, txHash)
		if err == nil {
			if receipt.Status == 0 {
				log.Error().Str("tx_hash", txHash.Hex()).Msg("event identity registration transaction failed")
				return
			}

			expirationBlockNumber := receipt.BlockNumber.Uint64() + ttl
			err = uc.dbQuery.UpdateEventIdentityRegistrationExpirationBlockNumber(ctx, data.UpdateEventIdentityRegistrationExpirationBlockNumberParams{
				ExpirationBlockNumber: int64(expirationBlockNumber),
				Eon:                   int64(eon),
				IdentityPrefix:        identityPrefix,
				Sender:                sender,
			})
			if err != nil {
				log.Err(err).Str("tx_hash", txHash.Hex()).Msg("failed to update expiration block number")
			}
			return
		}

		<-ticker.C
	}
}

func (uc *CryptoUsecase) GetEventTriggerExpirationBlock(ctx context.Context, eon uint64, identityPrefix string) (*GetEventTriggerExpirationBlockResponse, *httpError.Http) {
	identityPrefixBytes, err := hex.DecodeString(strings.TrimPrefix(identityPrefix, "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding identity prefix")
		err := httpError.NewHttpError(
			"error encountered while decoding identity prefix",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	if len(identityPrefixBytes) != 32 {
		log.Err(err).Msg("identity prefix should be of length 32")
		err := httpError.NewHttpError(
			"identity prefix should be of length 32",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	address := crypto.PubkeyToAddress(uc.config.SigningKey.PublicKey)
	sender := address.Hex()

	expirationBlockNumber, err := uc.dbQuery.GetEventTriggerExpirationBlockNumber(ctx, data.GetEventTriggerExpirationBlockNumberParams{
		Eon:            int64(eon),
		IdentityPrefix: identityPrefixBytes,
		Sender:         sender,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Debug().Uint64("eon", eon).Str("identityPrefix", identityPrefix).Str("sender", sender).Msg("event identity registration not found")
			err := httpError.NewHttpError(
				"event identity registration not found",
				"",
				http.StatusNotFound,
			)
			return nil, &err
		}
		log.Err(err).Msg("err encountered while querying event identity registration expiration block number")
		err := httpError.NewHttpError(
			"error encountered while querying event identity registration expiration block number",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	return &GetEventTriggerExpirationBlockResponse{
		ExpirationBlockNumber: uint64(expirationBlockNumber),
	}, nil
}
