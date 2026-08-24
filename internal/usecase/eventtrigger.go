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

	"github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/data"
	httpError "github.com/shutter-network/shutter-api/internal/error"
	sherror "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/internal/txmgr"
	"github.com/shutter-network/shutter-api/metrics"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

type EventArgument struct {
	Name     string `json:"name" example:"amount"`
	Operator string `json:"op" example:"gte"`
	Number   string `json:"number" example:"25433"`
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
	lp.LogValueRef.Offset = 0
	h := crypto.Keccak256([]byte(b.String()))
	lp.ValuePredicate.ByteArgs = [][]byte{h}
	lp.ValuePredicate.Op = shs.BytesEq
	return lp
}

func offsetByName(inputs []sigparser.Parameter) map[string]uint64 {
	offsets := make(map[string]uint64, len(inputs))
	nonIndexed := uint64(4)
	indexed := uint64(1)
	for _, input := range inputs {
		if input.Indexed {
			offsets[input.Name] = indexed
			indexed += 1
		} else {
			offsets[input.Name] = nonIndexed
			nonIndexed += 1
		}
	}
	return offsets
}

func logPredicates(args []EventArgument, evtSig string) ([]shs.LogPredicate, error) {
	lps := []shs.LogPredicate{}
	sig, err := sigparser.ParseSignature(evtSig)
	if err != nil {
		return lps, err
	}
	lp := Topic0(sig)
	lps = append(lps, lp)
	offsets := offsetByName(sig.Inputs)
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
				if arg.Operator != "eq" {
					return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
				}
				lp.ValuePredicate.Op = shs.BytesEq
				lp.ValuePredicate.ByteArgs = [][]byte{Align(val)}
				// input is data argument:
			} else {
				lp.LogValueRef.Dynamic = isDynamicType(input.Type)
				if input.Type != "uint256" {
					val, err := hexutil.Decode(arg.Bytes)
					if err != nil {
						return lps, err
					}
					if arg.Operator != "eq" {
						return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
					}
					lp.ValuePredicate.Op = shs.BytesEq
					lp.ValuePredicate.ByteArgs = [][]byte{val}
				} else {
					switch strings.ToLower(arg.Operator) {
					case "lt":
						lp.ValuePredicate.Op = shs.UintLt
					case "lte":
						lp.ValuePredicate.Op = shs.UintLte
					case "eq":
						lp.ValuePredicate.Op = shs.UintEq
					case "gt":
						lp.ValuePredicate.Op = shs.UintGt
					case "gte":
						lp.ValuePredicate.Op = shs.UintGte
					default:
						return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
					}
					num, ok := big.NewInt(0).SetString(arg.Number, 10)
					if !ok {
						return lps, fmt.Errorf("cannot interpret %v as a decimal string (don't use literal int)", arg.Number)
					}
					lp.ValuePredicate.IntArgs = []*big.Int{num}
				}
			}
			lp.LogValueRef.Offset = offsets[arg.Name]
			lps = append(lps, lp)
		}
	}
	return lps, nil
}

func isDynamicType(typeName string) bool {
	switch typeName {
	case "bytes":
		return true
	case "string":
		return true
	default:
		return false
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
		metrics.FailedRPCCalls.Inc()
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
		metrics.FailedRPCCalls.Inc()
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
		metrics.FailedRPCCalls.Inc()
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

	sender := uc.txManager.From()
	identity := common.ComputeEventIdentity(identityPrefix[:], sender, eventTriggerDefinition)

	_, err = uc.dbQuery.GetEventIdentityRegistration(ctx, data.GetEventIdentityRegistrationParams{
		Eon:      int64(eon),
		Identity: identity,
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

	events := uc.txManager.Send(func(opts *bind.TransactOpts) (*types.Transaction, error) {
		return uc.shutterEventRegistryContract.Register(opts, eon, identityPrefix, eventTriggerDefinition, ttl)
	})
	registration := data.InsertEventIdentityRegistrationParams{
		Eon:                    int64(eon),
		Identity:               identity,
		IdentityPrefix:         identityPrefix[:],
		Sender:                 sender.Hex(),
		EventTriggerDefinition: eventTriggerDefinition,
	}

	txHash, httpErr := awaitSubmission(ctx, events)
	if httpErr != nil {
		// Giving up waiting does not stop the transaction, so an identity may yet
		// be registered on chain that the API has no record of. Hand the request
		// over instead of dropping it, and let the row be written when the
		// transaction turns up.
		go uc.recordEventRegistration(events, registration, ttl, false)
		return nil, httpErr
	}

	registration.TxHash = txHash.Bytes()
	err = uc.dbQuery.InsertEventIdentityRegistration(ctx, registration)
	if err != nil {
		// The transaction is already on its way, so the registration happens
		// whether or not this worked. Answering with an error would be a lie;
		// recordEventRegistration gets another attempt at the row instead.
		log.Err(err).Msg("err encountered while storing event identity registration")
	}

	go uc.recordEventRegistration(events, registration, ttl, err == nil)

	metrics.SuccessfulIdentityRegistrations.Inc()
	return &RegisterIdentityResponse{
		Eon:            eon,
		Identity:       common.PrefixWith0x(hex.EncodeToString(identity)),
		IdentityPrefix: common.PrefixWith0x(hex.EncodeToString(identityPrefix[:])),
		EonKey:         common.PrefixWith0x(hex.EncodeToString(eonKeyBytes)),
		TxHash:         txHash.Hex(),
	}, nil
}

// recordEventRegistration follows a registration to its conclusion and keeps the
// database in step with it. It runs in a goroutine of its own because it outlives
// the request by design: the response is committed as soon as there is a hash,
// while the transaction is only mined blocks later.
//
// inserted says whether the row already exists. A request that gave up waiting, or
// whose own insert failed, leaves it to this, so that an identity registered on
// chain is not one the API has no record of.
func (uc *CryptoUsecase) recordEventRegistration(
	events <-chan txmgr.Event,
	registration data.InsertEventIdentityRegistrationParams,
	ttl uint64,
	inserted bool,
) {
	// Deliberately not the request's context, which is cancelled once the response
	// is written. Reading stops on its own when the manager ends the request.
	ctx := context.Background()

	for ev := range events {
		switch {
		case ev.Tx != nil:
			registration.TxHash = ev.Tx.Hash().Bytes()
			if !inserted {
				inserted = uc.insertEventRegistration(ctx, registration)
			}
		case ev.Receipt != nil:
			registration.TxHash = ev.Receipt.TxHash.Bytes()
			if !inserted {
				uc.insertEventRegistration(ctx, registration)
			}
			uc.recordExpirationBlockNumber(ctx, registration, ttl, ev.Receipt)
		case ev.Err != nil:
			log.Err(ev.Err).
				Str("identity", hex.EncodeToString(registration.Identity)).
				Msg("event identity registration was not mined")
		}
	}
}

// insertEventRegistration writes the registration row and reports whether that
// worked. A failure is logged rather than retried, because the next event is
// another chance at it.
func (uc *CryptoUsecase) insertEventRegistration(ctx context.Context, registration data.InsertEventIdentityRegistrationParams) bool {
	if err := uc.dbQuery.InsertEventIdentityRegistration(ctx, registration); err != nil {
		log.Err(err).Str("tx_hash", hex.EncodeToString(registration.TxHash)).
			Msg("err encountered while storing event identity registration")
		return false
	}
	return true
}

// recordExpirationBlockNumber fills in the block the registration expires at,
// which cannot be known before the transaction is mined.
func (uc *CryptoUsecase) recordExpirationBlockNumber(
	ctx context.Context,
	registration data.InsertEventIdentityRegistrationParams,
	ttl uint64,
	receipt *types.Receipt,
) {
	if receipt.Status == types.ReceiptStatusFailed {
		log.Error().Str("tx_hash", receipt.TxHash.Hex()).
			Msg("event identity registration transaction reverted")
		return
	}

	err := uc.dbQuery.UpdateEventIdentityRegistrationExpirationBlockNumber(ctx, data.UpdateEventIdentityRegistrationExpirationBlockNumberParams{
		ExpirationBlockNumber: int64(receipt.BlockNumber.Uint64() + ttl),
		Eon:                   registration.Eon,
		Identity:              registration.Identity,
	})
	if err != nil {
		log.Err(err).Str("tx_hash", receipt.TxHash.Hex()).
			Msg("failed to update expiration block number")
	}
}

func (uc *CryptoUsecase) GetEventTriggerExpirationBlock(ctx context.Context, eon uint64, identity string) (*GetEventTriggerExpirationBlockResponse, *httpError.Http) {
	identityBytes, err := hex.DecodeString(strings.TrimPrefix(identity, "0x"))
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

	sender := uc.txManager.From().Hex()

	expirationBlockNumber, err := uc.dbQuery.GetEventTriggerExpirationBlockNumber(ctx, data.GetEventTriggerExpirationBlockNumberParams{
		Eon:      int64(eon),
		Identity: identityBytes,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Debug().Uint64("eon", eon).Str("identity", identity).Str("sender", sender).Msg("event identity registration not found")
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

func (uc *CryptoUsecase) GetEventDecryptionKey(ctx context.Context, identity string, eon int64) (*GetDecryptionKeyResponse, *httpError.Http) {
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

	if eon < 0 {
		blockNumber, err := uc.ethClient.BlockNumber(ctx)
		if err != nil {
			log.Err(err).Msg("err encountered while querying for recent block")
			metrics.FailedRPCCalls.Inc()
			err := httpError.NewHttpError(
				"error encountered while querying for recent block",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}

		eonUint, err := uc.keyperSetManagerContract.GetKeyperSetIndexByBlock(nil, blockNumber)
		if err != nil {
			log.Err(err).Msg("err encountered while querying current eon")
			metrics.FailedRPCCalls.Inc()
			err := httpError.NewHttpError(
				"error encountered while querying current eon",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
		eon = int64(eonUint)

	}
	arg := data.GetDecryptionKeyParams{
		EpochID: []byte(identityBytes),
		Eon:     int64(eon),
	}

	var decryptionKey string

	decKey, err := uc.dbQuery.GetDecryptionKey(ctx, arg)
	if err != nil {
		if err == pgx.ErrNoRows {
			// no data found try querying from other keyper via http
			decKey, err := uc.getDecryptionKeyFromExternalKeyper(ctx, int64(arg.Eon), identity)
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
					"decryption key doesn't exist",
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
		DecryptionTimestamp: 0, // FIXME: ensure, we can fill timestamp for event based keys
	}, nil
}
