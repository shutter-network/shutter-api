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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
	"github.com/shutter-network/shutter-api/common"
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
	EventSignature  string          `json:"event_sig" example:"Transfer(indexed from address, indexed to address, amount uint256)"`
	ContractAddress ecommon.Address `json:"contract" example:"0x3465a347342B72BCf800aBf814324ba4a803c32b"`
	Arguments       []EventArgument `json:"arguments" example:"[{\"name\": \"from\", \"op\": \"eq\", \"bytes\": \"0x456d9347342B72BCf800bBf117391ac2f807c6bF\"}]"`
} // @name EventTriggerDefinitionRequest

type EventTriggerDefinitionResponse struct {
	EventTriggerDefinition string `json:"triggerDefinition" example:"Transfer(indexed from address, indexed to address, amount uint256)"`
}

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

	data := EventTriggerDefinitionResponse{EventTriggerDefinition: hex.EncodeToString(etd.MarshalBytes())}
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
					length = uint64(len([]byte(arg.Bytes)) / 32)
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

	// TODO: check for already registered identities also against time based triggers!

	publicAddress := crypto.PubkeyToAddress(*uc.config.PublicKey)

	opts := bind.TransactOpts{
		From:   publicAddress,
		Signer: newSigner.Signer,
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

	// TODO: check contract address of eventTriggerDefinition against white list (if necessary)
	// whitelist from ENV - if empty assert wildcard
	// - parse event trigger definition with keyper side code from keyperimpl/shutterservice.EventTriggerDefinition
	// - check event trigger definition "Contract" against whitelist

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

	metrics.TotalSuccessfulIdentityRegistration.Inc()
	return &RegisterIdentityResponse{
		Eon:            eon,
		Identity:       common.PrefixWith0x(hex.EncodeToString(identity)),
		IdentityPrefix: common.PrefixWith0x(hex.EncodeToString(identityPrefix[:])),
		EonKey:         common.PrefixWith0x(hex.EncodeToString(eonKeyBytes)),
		TxHash:         tx.Hash().Hex(),
	}, nil

}
