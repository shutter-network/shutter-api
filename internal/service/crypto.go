package service

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"

	sigparser "github.com/defiweb/go-sigparser"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-api/common"
	sherror "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/internal/usecase"

	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
)

type RegisterIdentityRequest struct {
	DecryptionTimestamp uint64 `json:"decryptionTimestamp" example:"1735044061"`
	IdentityPrefix      string `json:"identityPrefix" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
} // @name RegisterIdentityRequest

type EventArgument struct {
	Name     string `json:"name" example:"amount"`
	Operator string `json:"op" example:">="`
	Value    string `json:"value" example:"25433"`
}
type EventTriggerDefinitionRequest struct {
	ABI             string          `json:"eventABI" example:"Transfer(indexed from address, indexed to address, amount uint256)"`
	ContractAddress ecommon.Address `json:"contract" example:"0x3465a347342B72BCf800aBf814324ba4a803c32b"`
	Arguments       []EventArgument `json:"arguments" example:"[{\"name\": \"from\", \"operator\": \"==\", \"value\": \"0x456d9347342B72BCf800bBf117391ac2f807c6bF\"}]"`
}
type EventTriggerDefinitionResponse struct {
	EventTriggerDefinition string `json:"event_trigger_definition" example:"Transfer(indexed from address, indexed to address, amount uint256)"`
}

type CryptoService struct {
	CryptoUsecase *usecase.CryptoUsecase
}

func NewCryptoService(
	db *pgxpool.Pool,
	contract *common.Contract,
	ethClient *ethclient.Client,
	config *common.Config,
) *CryptoService {
	return &CryptoService{
		CryptoUsecase: usecase.NewCryptoUsecase(db, contract.ShutterRegistryContract, contract.KeyperSetManagerContract, contract.KeyBroadcastContract, ethClient, config),
	}
}

//	@BasePath	/api

// GetDecryptionKey godoc
//	@Summary		Get decryption key.
//	@Description	Retrieves a decryption key for a given registered identity once the timestamp is reached. Decryption key is 0x padded, clients need to remove the prefix when decrypting on their end.
//	@Tags			Crypto
//	@Produce		json
//	@Param			identity	query		string								true	"Identity associated with the decryption key."
//	@Success		200			{object}	usecase.GetDecryptionKeyResponse	"Success."
//	@Failure		400			{object}	error.Http							"Invalid Get decryption key request."
//	@Failure		404			{object}	error.Http							"Decryption key not found for the associated identity."
//	@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//	@Failure		500			{object}	error.Http							"Internal server error."
//  @Security		BearerAuth
//	@Router			/get_decryption_key [get]

func (svc *CryptoService) GetDecryptionKey(ctx *gin.Context) {
	identity, ok := ctx.GetQuery("identity")
	if !ok {
		err := sherror.NewHttpError(
			"query parameter not found",
			"identity query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, err := svc.CryptoUsecase.GetDecryptionKey(ctx, identity)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

//	@BasePath	/api

// GetDataForEncryption godoc
//	@Summary		Provides data necessary to allow encryption.
//	@Description	Retrieves all the necessary data required by clients for encrypting any message.
//	@Tags			Crypto
//	@Produce		json
//	@Param			address			query		string									true	"Ethereum address associated with the identity. If you are registering the identity yourself, pass the address of the account making the registration. If you want the API to register the identity on gnosis mainnet, pass the address: 0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc. For chiado pass the address: 0xb9C303443c9af84777e60D5C987AbF0c43844918"
//	@Param			identityPrefix	query		string									false	"Optional identity prefix. You can generate it on your end and pass it to this endpoint, or allow the API to randomly generate one for you."
//	@Success		200				{object}	usecase.GetDataForEncryptionResponse	"Success."
//	@Failure		400				{object}	error.Http								"Invalid Get data for encryption request."
//	@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//	@Failure		500			{object}	error.Http							"Internal server error."
//  @Security		BearerAuth
//	@Router			/get_data_for_encryption [get]

func (svc *CryptoService) GetDataForEncryption(ctx *gin.Context) {
	address, ok := ctx.GetQuery("address")
	if !ok {
		err := sherror.NewHttpError(
			"query parameter not found",
			"address query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	identityPrefix, ok := ctx.GetQuery("identityPrefix")
	if !ok {
		identityPrefix = ""
	}

	data, httpErr := svc.CryptoUsecase.GetDataForEncryption(ctx, address, identityPrefix)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

//	@BasePath	/api

// RegisterIdentity godoc
//	@Summary		Allows clients to register any identity.
//	@Description	Allows clients to register an identity used for encryption and specify a release timestamp for the decryption key associated with the encrypted message.
//	@Tags			Crypto
//	@Accepts		json
//	@Produce		json
//	@Param			request	body		RegisterIdentityRequest				true	"Timestamp and Identity which client want to make the registration with."
//	@Success		200		{object}	usecase.RegisterIdentityResponse	"Success."
//	@Failure		400		{object}	error.Http							"Invalid Register identity request."
//	@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//	@Failure		500			{object}	error.Http							"Internal server error."
//  @Security		BearerAuth
//	@Router			/register_identity [post]

func (svc *CryptoService) RegisterIdentity(ctx *gin.Context) {
	var req RegisterIdentityRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Err(err).Msg("err decoding request body")
		err := sherror.NewHttpError(
			"unable to decode request body",
			"",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, httpErr := svc.CryptoUsecase.RegisterIdentity(ctx, req.DecryptionTimestamp, req.IdentityPrefix)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

//	@BasePath	/api

// DecryptCommitment godoc
//	@Summary		Allows clients to decrypt their encrypted message.
//	@Description	Provides a way for clients to easily decrypt their encrypted message for which they have registered the identity for. Timestamp with which the identity was registered should have been passed for the message to be decrypted successfully.
//	@Tags			Crypto
//	@Produce		json
//	@Param			identity			query		string		true	"Identity used for registeration and encrypting the message."
//	@Param			encryptedCommitment	query		string		true	"Encrypted commitment is the clients encrypted message."
//	@Success		200					{object}	[]byte		"Success."
//	@Failure		400					{object}	error.Http	"Invalid Decrypt commitment request."
//	@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//	@Failure		500			{object}	error.Http							"Internal server error."
//  @Security		BearerAuth
//	@Router			/decrypt_commitment [get]

func (svc *CryptoService) DecryptCommitment(ctx *gin.Context) {
	identity, ok := ctx.GetQuery("identity")
	if !ok {
		err := sherror.NewHttpError(
			"query parameter not found",
			"identity query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	encryptedCommitment, ok := ctx.GetQuery("encryptedCommitment")
	if !ok {
		err := sherror.NewHttpError(
			"query parameter not found",
			"encrypted commitment query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, err := svc.CryptoUsecase.DecryptCommitment(ctx, encryptedCommitment, identity)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

//	@BasePath	/api

// EventTriggerDefinition godoc
//	@Summary		Allows clients to compile an event trigger definition string.
//	@Description	This endpoint takes an ABI snippet and some arguments to create an event trigger definition that will be understood by keypers supporting event based decryption triggers.
//	@Tags			Crypto
//	@Produce		json
//	@Param			request	body		EventDefinitionRequest				true	"Event ABI and operator-arguments tuples to match."
//	@Success		200					{object}	[]byte		"Success."
//	@Failure		400					{object}	error.Http	"Invalid Event Data."
//	@Failure		429					{object}	error.Http							"Too many requests. Rate limited."
//	@Failure		500					{object}	error.Http							"Internal server error."
//  @Security		BearerAuth
//	@Router			/event_trigger_definition [post]

func (svc *CryptoService) CompileEventTriggerDefinition(ctx *gin.Context) {
	CompileEventTriggerDefinition(ctx)
}

func CompileEventTriggerDefinition(ctx *gin.Context) {
	var req EventTriggerDefinitionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Err(err).Msg("err decoding request body")
		err := sherror.NewHttpError(
			"unable to decode request body, JSON invalid",
			err.Error(),
			http.StatusBadRequest,
		)
		ctx.Error(err)
	}
	resp, errors := CompileEventTriggerDefinitionInternal(req)
	if len(errors) > 0 {
		for _, err := range errors {
			ctx.Error(err)
		}
		ctx.JSON(http.StatusBadRequest, ctx.Errors.JSON())
	} else {
		ctx.JSON(http.StatusOK, resp)
	}
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
	if len(req.ABI) == 0 {
		err := fmt.Errorf("No ABI given")
		log.Err(err).Msg("error creating event trigger definition")
		err = sherror.NewHttpError(
			"unable to parse event trigger definition",
			err.Error(),
			http.StatusBadRequest,
		)
		errors = append(errors, err)
	}
	predicates, err := logPredicates(req.Arguments, req.ABI)
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
func align(val []byte) []byte {
	words := (31 + len(val)) / shs.Word
	x := make([]byte, shs.Word*words)
	copy(x[len(x)-len(val):], val)
	return x
}

func topic0(sig sigparser.Signature) shs.LogPredicate {
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

func logPredicates(args []EventArgument, evtABI string) ([]shs.LogPredicate, error) {
	lps := []shs.LogPredicate{}
	sig, err := sigparser.ParseSignature(evtABI)
	if err != nil {
		return lps, err
	}
	lp := topic0(sig)
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
			return lps, fmt.Errorf("argument '%v' not defined in ABI", arg.Name)
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
				val, err := hexutil.Decode(arg.Value)
				if err != nil {
					return lps, err
				}
				length = 1
				if arg.Operator != "eq" {
					return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
				}
				lp.ValuePredicate.Op = shs.BytesEq
				lp.ValuePredicate.ByteArgs = [][]byte{align(val)}
				lp.LogValueRef.Offset = indexedOffset
				indexedOffset++
				// input is data argument:
			} else {
				if input.Type != "uint256" {
					val, err := hexutil.Decode(arg.Value)
					if err != nil {
						return lps, err
					}
					if arg.Operator != "eq" {
						return lps, fmt.Errorf("invalid operator '%v' for input '%v' of type '%v'", arg.Operator, input.Name, input.Type)
					}
					lp.ValuePredicate.Op = shs.BytesEq
					lp.ValuePredicate.ByteArgs = [][]byte{align(val)}
					length = uint64(len([]byte(arg.Value)) / 32)
				} else {
					lp.ValuePredicate.Op = opFromString(arg.Operator)
					value, err := strconv.Atoi(arg.Value)
					if err != nil {
						return lps, err
					}
					lp.ValuePredicate.IntArgs = []*big.Int{big.NewInt(int64(value))}
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
