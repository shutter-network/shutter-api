package service

import (
	"net/http"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-api/common"
	sherror "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/internal/usecase"
)

type RegisterIdentityRequest struct {
	DecryptionTimestamp uint64 `json:"decryptionTimestamp" example:"1735044061"`
	IdentityPrefix      string `json:"identityPrefix" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
} // @name RegisterIdentityRequest

type RegisterEventIdentityRequest struct {
	EventTriggerDefinitionHex string `json:"triggerDefinition" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
	IdentityPrefix            string `json:"identityPrefix" example:"0x79bc8f6b4fcb02c651d6a702b7ad965c7fca19e94a9646d21ae90c8b54c030a0"`
	Ttl                       uint64 `json:"ttl" example:"100"`
} // @name RegisterEventIdentityRequest

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
		CryptoUsecase: usecase.NewCryptoUsecase(db, contract.ShutterRegistryContract, contract.ShutterEventRegistryContract, contract.KeyperSetManagerContract, contract.KeyBroadcastContract, ethClient, config),
	}
}

//	@BasePath	/api
//
// GetDecryptionKey godoc
//
//		@Summary		Get decryption key.
//		@Description	Retrieves a decryption key for a given registered identity once the timestamp is reached. Decryption key is 0x padded, clients need to remove the prefix when decrypting on their end.
//		@Tags			Crypto
//		@Produce		json
//		@Param			identity	query		string								true	"Identity associated with the decryption key."
//		@Success		200			{object}	usecase.GetDecryptionKeyResponse	"Success."
//		@Failure		400			{object}	error.Http							"Invalid Get decryption key request."
//		@Failure		404			{object}	error.Http							"Decryption key not found for the associated identity."
//		@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//		@Failure		500			{object}	error.Http							"Internal server error."
//	 	@Security		BearerAuth
//		@Router			/get_decryption_key [get]
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
//
// GetDataForEncryption godoc
//
//		@Summary		Provides data necessary to allow encryption.
//		@Description	Retrieves all the necessary data required by clients for encrypting any message.
//		@Tags			Crypto
//		@Produce		json
//		@Param			address			query		string									true	"Ethereum address associated with the identity. If you are registering the identity yourself, pass the address of the account making the registration. If you want the API to register the identity on gnosis mainnet, pass the address: 0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc. For chiado pass the address: 0xb9C303443c9af84777e60D5C987AbF0c43844918"
//		@Param			identityPrefix	query		string									false	"Optional identity prefix. You can generate it on your end and pass it to this endpoint, or allow the API to randomly generate one for you."
//		@Success		200				{object}	usecase.GetDataForEncryptionResponse	"Success."
//		@Failure		400				{object}	error.Http								"Invalid Get data for encryption request."
//		@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//		@Failure		500			{object}	error.Http							"Internal server error."
//	 	@Security		BearerAuth
//		@Router			/get_data_for_encryption [get]
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
//
// RegisterIdentity godoc
//
//		@Summary		Allows clients to register any identity.
//		@Description	Allows clients to register an identity used for encryption and specify a release timestamp for the decryption key associated with the encrypted message.
//		@Tags			Crypto
//		@Accepts		json
//		@Produce		json
//		@Param			request	body		RegisterIdentityRequest				true	"Timestamp and Identity which client want to make the registration with."
//		@Success		200		{object}	usecase.RegisterIdentityResponse	"Success."
//		@Failure		400		{object}	error.Http							"Invalid Register identity request."
//		@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//		@Failure		500			{object}	error.Http							"Internal server error."
//	 	@Security		BearerAuth
//		@Router			/register_identity [post]
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
//
// DecryptCommitment godoc
//
//		@Summary		Allows clients to decrypt their encrypted message.
//		@Description	Provides a way for clients to easily decrypt their encrypted message for which they have registered the identity for. Timestamp with which the identity was registered should have been passed for the message to be decrypted successfully.
//		@Tags			Crypto
//		@Produce		json
//		@Param			identity			query		string		true	"Identity used for registeration and encrypting the message."
//		@Param			encryptedCommitment	query		string		true	"Encrypted commitment is the clients encrypted message."
//		@Success		200					{object}	[]byte		"Success."
//		@Failure		400					{object}	error.Http	"Invalid Decrypt commitment request."
//		@Failure		429			{object}	error.Http							"Too many requests. Rate limited."
//		@Failure		500			{object}	error.Http							"Internal server error."
//	 	@Security		BearerAuth
//		@Router			/decrypt_commitment [get]
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
//
// # EventTriggerDefinition godoc
//
//		@Summary		Allows clients to compile an event trigger definition string.
//		@Description	This endpoint takes an event signature snippet and some arguments to create an event trigger definition that will be understood by keypers
//						supporting event based decryption triggers. Example request body:
//						{
//	  						"contract": "0x3465a347342B72BCf800aBf814324ba4a803c32b",
//	  						"event_sig": "Transfer(indexed from address, indexed to address, amount uint256)",
//	  						"arguments": [
//	    							{ "name": "from", "op": "eq", "bytes": "0x456d9347342B72BCf800bBf117391ac2f807c6bF" },
//	    							{ "name": "amount", "op": "gte", "number": 25433 }
//	  							]
//							}
//						The object format for the "arguments" list is:
//						- "name": <matching argument name from signature>
//						- "op": <one of: lt, lte, eq, gte, gt>
//						- "number": <integer argument for numeric comparison>
//						- "bytes": <hex encoded byte argument for non numeric matches with 'op==eq'>
//						Note: the resulting condition for the trigger is a logical AND of all arguments given.
//
//		@Tags			Crypto
//		@Produce		json
//		@Param			request	body		EventTriggerDefinitionRequest		true	"Event signature and match arguments."
//		@Success		200		{object}	usecase.EventTriggerDefinitionResponse	"Success."
//		@Failure		400		{object}	error.Http							"Invalid Event Data."
//		@Failure		429		{object}	error.Http							"Too many requests. Rate limited."
//		@Failure		500		{object}	error.Http							"Internal server error."
//		@Security		BearerAuth
//		@Router			/compile_event_trigger_definition [post]
func (svc *CryptoService) CompileEventTriggerDefinition(ctx *gin.Context) {
	CompileEventTriggerDefinition(ctx)
}

func CompileEventTriggerDefinition(ctx *gin.Context) {
	var req usecase.EventTriggerDefinitionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Err(err).Msg("err decoding request body")
		err := sherror.NewHttpError(
			"unable to decode request body, JSON invalid",
			err.Error(),
			http.StatusBadRequest,
		)
		ctx.Error(err)
	}
	resp, errors := usecase.CompileEventTriggerDefinitionInternal(req)
	if len(errors) > 0 {
		for _, err := range errors {
			ctx.Error(err)
		}
		ctx.JSON(http.StatusBadRequest, ctx.Errors.JSON())
	} else {
		ctx.JSON(http.StatusOK, resp)
	}
}

//	@BasePath	/api
//
// RegisterEventIdentity godoc
//
//		@Summary		Allows clients to register an event trigger identity.
//		@Description	Allows clients to register an identity used for encryption and event trigger definition for the decryption key associated with the encrypted message.
//		@Tags			Crypto
//		@Accepts		json
//		@Produce		json
//		@Param			request	body		RegisterEventIdentityRequest		true	"Event trigger definition, ttl and Identity which client want to make the registration with."
//		@Success		200		{object}	usecase.RegisterIdentityResponse		"Success."
//		@Failure		400		{object}	error.Http							"Invalid Register identity request."
//		@Failure		429			{object}	error.Http						"Too many requests. Rate limited."
//		@Failure		500			{object}	error.Http						"Internal server error."
//	 	@Security		BearerAuth
//		@Router			/register_event_identity [post]
func (svc *CryptoService) RegisterEventIdentity(ctx *gin.Context) {

	var req RegisterEventIdentityRequest
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

	data, httpErr := svc.CryptoUsecase.RegisterEventIdentity(ctx, req.EventTriggerDefinitionHex, req.IdentityPrefix, req.Ttl)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}
