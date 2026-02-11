package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cryptorand "crypto/rand"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shutter-network/shutter-api/common"
	httpError "github.com/shutter-network/shutter-api/internal/error"
	"github.com/shutter-network/shutter-api/internal/service"
	"github.com/shutter-network/shutter-api/internal/usecase"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var msg = []byte("please hide this message")

func (s *TestShutterService) TestRequestDecryptionKeyBeforeTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityStringified := res.Identity

	decryptionTimestamp := time.Now().Add(1 * time.Hour).Unix()

	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	s.registerIdentityRequest(jsonData, http.StatusOK)

	time.Sleep(30 * time.Second)

	errorResponse := s.getDecryptionKeyRequestError(identityStringified, http.StatusBadRequest)
	s.Require().Equal("timestamp not reached yet, decryption key requested too early", errorResponse.Description)
}

func (s *TestShutterService) TestRequestDecryptionKeyAfterTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	ctx := context.Background()
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityBytes, err := hex.DecodeString(strings.TrimPrefix(res.Identity, "0x"))
	s.Require().NoError(err)

	eonKeyBytes, err := hex.DecodeString(strings.TrimPrefix(res.EonKey, "0x"))
	s.Require().NoError(err)

	epochID := shcrypto.ComputeEpochID(identityBytes)

	eonPublicKey := &shcrypto.EonPublicKey{}
	err = eonPublicKey.Unmarshal(eonKeyBytes)
	s.Require().NoError(err)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)

	encryptedMessage := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)

	block, err := s.ethClient.BlockByNumber(ctx, nil)
	s.Require().NoError(err)

	// Use a timestamp that's far enough in the future to avoid timing issues
	// but close enough that we don't have to wait too long
	decryptionTimestamp := block.Header().Time + 40
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	s.registerIdentityRequest(jsonData, http.StatusOK)

	time.Sleep(45 * time.Second)

	decryptionKeyResponse := s.getDecryptionKeyRequest(res.Identity, http.StatusOK)

	decryptionKeyStringified := decryptionKeyResponse["message"].DecryptionKey
	s.Require().NotEmpty(decryptionKeyStringified)

	decryptionKey := &shcrypto.EpochSecretKey{}
	decryptionKeyBytes, err := hex.DecodeString(strings.TrimPrefix(decryptionKeyStringified, "0x"))
	s.Require().NoError(err)
	err = decryptionKey.Unmarshal(decryptionKeyBytes)
	s.Require().NoError(err)

	decryptedMessage, err := encryptedMessage.Decrypt(decryptionKey)
	s.Require().NoError(err)
	s.Require().Equal(msg, decryptedMessage)
}

func (s *TestShutterService) TestRequestDecryptionKeyForUnregisteredIdentity() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	errorResponse := s.getDecryptionKeyRequestError(res.Identity, http.StatusBadRequest)
	s.Require().Equal("identity has not been registerd yet", errorResponse.Description)
}

func (s *TestShutterService) TestRequestDecryptCommitmentAfterTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	ctx := context.Background()
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityBytes, err := hex.DecodeString(strings.TrimPrefix(res.Identity, "0x"))
	s.Require().NoError(err)

	eonKeyBytes, err := hex.DecodeString(strings.TrimPrefix(res.EonKey, "0x"))
	s.Require().NoError(err)

	epochID := shcrypto.ComputeEpochID(identityBytes)

	eonPublicKey := &shcrypto.EonPublicKey{}
	eonPublicKey.Unmarshal(eonKeyBytes)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)

	encryptedCommitment := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)
	encrypedCommitmentBytes := encryptedCommitment.Marshal()
	encryptedCommitmentStringified := hex.EncodeToString(encrypedCommitmentBytes)

	block, err := s.ethClient.BlockByNumber(ctx, nil)
	s.Require().NoError(err)
	decryptionTimestamp := block.Header().Time + 20
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	s.registerIdentityRequest(jsonData, http.StatusOK)

	time.Sleep(40 * time.Second)

	reqBody = service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp + 120),
		IdentityPrefix:      identityPrefixStringified,
	}
	jsonData, err = json.Marshal(reqBody)
	s.Require().NoError(err)
	errRegisterIdentity := s.registerIdentityRequestError(jsonData, http.StatusBadRequest)
	s.Require().Equal("identity already registered", errRegisterIdentity.Description)

	query := fmt.Sprintf("?identity=%s&encryptedCommitment=%s", res.Identity, encryptedCommitmentStringified)
	url := "/api/decrypt_commitment" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var decryptionKeyResponse map[string]string
	err = json.Unmarshal(body, &decryptionKeyResponse)
	s.Require().NoError(err)

	decryptedMessage := decryptionKeyResponse["message"]

	s.Require().NotEmpty(decryptedMessage)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(msg)), decryptedMessage)
}

func (s *TestShutterService) TestRegisterIdentityInThePast() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	ctx := context.Background()
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	block, err := s.ethClient.BlockByNumber(ctx, nil)
	s.Require().NoError(err)

	decryptionTimestamp := block.Header().Time - 10
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)

	errorResponse := s.registerIdentityRequestError(jsonData, http.StatusBadRequest)
	s.Require().Equal("decryption timestamp should be in future", errorResponse.Description)
}

func (s *TestShutterService) TestBulkRequestDecryptionKeyAfterTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	totalBulkRequests, err := strconv.Atoi(os.Getenv("TOTAL_BULK_REQUESTS"))
	if err != nil {
		totalBulkRequests = 3
	}

	encryptedMessages := make([]*shcrypto.EncryptedMessage, totalBulkRequests)
	identities := make([]string, totalBulkRequests)

	for i := 0; i < totalBulkRequests; i++ {
		id, err := generateRandomBytes(32)
		identityPrefix := crypto.Keccak256(bytes.Join([][]byte{id, []byte(strconv.Itoa(i))}, nil))
		s.Require().NoError(err)
		identityPrefixStringified := hex.EncodeToString(identityPrefix)

		dataForEncryptionResponse := s.getDataForEncryptionRequest(address, identityPrefixStringified)

		res := dataForEncryptionResponse["message"]
		s.Require().GreaterOrEqual(res.Eon, uint64(1))
		s.Require().NotNil(res.EonKey)
		s.Require().NotNil(res.Identity)
		s.Require().NotNil(res.IdentityPrefix)

		identityBytes, err := hex.DecodeString(strings.TrimPrefix(res.Identity, "0x"))
		s.Require().NoError(err)
		eonKeyBytes, err := hex.DecodeString(strings.TrimPrefix(res.EonKey, "0x"))
		s.Require().NoError(err)

		epochID := shcrypto.ComputeEpochID(identityBytes)
		eonPublicKey := &shcrypto.EonPublicKey{}
		err = eonPublicKey.Unmarshal(eonKeyBytes)
		s.Require().NoError(err)

		sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
		s.Require().NoError(err)
		encryptedMessage := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)
		encryptedMessages[i] = encryptedMessage

		decryptionTimestamp := time.Now().Unix() + 20

		reqBody := service.RegisterIdentityRequest{
			DecryptionTimestamp: uint64(decryptionTimestamp),
			IdentityPrefix:      identityPrefixStringified,
		}

		jsonData, err := json.Marshal(reqBody)
		s.Require().NoError(err)

		// Add a small delay between registrations to prevent nonce conflicts
		if i > 0 {
			time.Sleep(5 * time.Second)
		}
		s.registerIdentityRequest(jsonData, http.StatusOK)

		identities[i] = res.Identity
	}

	time.Sleep(60 * time.Second)

	for i := 0; i < totalBulkRequests; i++ {
		decryptionKeyResponse := s.getDecryptionKeyRequest(identities[i], http.StatusOK)
		decryptionKeyStringified := decryptionKeyResponse["message"].DecryptionKey
		s.Require().NotEmpty(decryptionKeyStringified)

		decryptionKey := &shcrypto.EpochSecretKey{}
		decryptionKeyBytes, err := hex.DecodeString(strings.TrimPrefix(decryptionKeyStringified, "0x"))
		s.Require().NoError(err)
		err = decryptionKey.Unmarshal(decryptionKeyBytes)
		s.Require().NoError(err)

		decryptedMessage, err := encryptedMessages[i].Decrypt(decryptionKey)
		s.Require().NoError(err)
		s.Require().Equal(msg, decryptedMessage)
	}
}

func (s *TestShutterService) registerIdentityRequest(jsonData []byte, statusCode int) {
	url := "/api/time/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)
}

func (s *TestShutterService) registerIdentityRequestError(jsonData []byte, statusCode int) httpError.Http {
	url := "/api/time/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	return errorResponse
}

func (s *TestShutterService) getDataForEncryptionRequest(address string, identityPrefix string) map[string]usecase.GetDataForEncryptionResponse {
	query := fmt.Sprintf("?address=%s&identityPrefix=%s", address, identityPrefix)
	url := "/api/time/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	return dataForEncryptionResponse
}

func (s *TestShutterService) getDecryptionKeyRequestError(identity string, statusCode int) httpError.Http {
	query := fmt.Sprintf("?identity=%s", identity)
	url := "/api/time/get_decryption_key" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	return errorResponse
}

func (s *TestShutterService) getDecryptionKeyRequest(identity string, statusCode int) map[string]usecase.GetDecryptionKeyResponse {
	query := fmt.Sprintf("?identity=%s", identity)
	url := "/api/time/get_decryption_key" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var decryptionKeyResponse map[string]usecase.GetDecryptionKeyResponse
	err = json.Unmarshal(body, &decryptionKeyResponse)
	s.Require().NoError(err)

	return decryptionKeyResponse
}

func (s *TestShutterService) TestCompileEventTriggerDefinition() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`
	jsonData := []byte(body)

	response := s.compileEventTriggerDefinitionRequest(jsonData, http.StatusOK)
	s.Require().NotEmpty(response.EventTriggerDefinition)
	s.Require().True(strings.HasPrefix(response.EventTriggerDefinition, "0x"))
}

func (s *TestShutterService) TestCompileEventTriggerDefinitionIncompleteRequest() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	testCases := []struct {
		name           string
		body           string
		expectedDesc   string
		expectedDetail string
	}{
		{
			name:           "missing contract",
			body:           `{"eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`,
			expectedDesc:   "unable to parse event trigger definition",
			expectedDetail: "Contract address empty",
		},
		{
			name:           "missing event signature",
			body:           `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`,
			expectedDesc:   "unable to parse event trigger definition",
			expectedDetail: "No event signature given",
		},
	}

	for _, testCase := range testCases {
		s.Run(testCase.name, func() {
			body := s.compileEventTriggerDefinitionRequestError([]byte(testCase.body), http.StatusBadRequest)
			s.Require().Contains(body, testCase.expectedDesc)
			s.Require().Contains(body, testCase.expectedDetail)
		})
	}
}

func (s *TestShutterService) TestGetDataForEncryptionEventMissingTriggerDefinition() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	errResp := s.getEventDataForEncryptionRequestError(identityPrefixStringified, http.StatusBadRequest)
	s.Require().Equal("triggerDefinition query parameter is required for event-based get_data_for_encryption", errResp.Metadata)
	s.Require().Equal("query parameter not found", errResp.Description)
}

func (s *TestShutterService) TestRegisterEventIdentityAndGetTriggerExpirationBlock() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`
	jsonData := []byte(body)

	triggerDefinitionResp := s.compileEventTriggerDefinitionRequest(jsonData, http.StatusOK)
	s.Require().NotEmpty(triggerDefinitionResp.EventTriggerDefinition)

	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	dataForEncryptionResponse := s.getEventDataForEncryptionRequest(triggerDefinitionResp.EventTriggerDefinition, identityPrefixStringified)
	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotEmpty(res.EonKey)
	s.Require().NotEmpty(res.Identity)
	s.Require().Equal(common.PrefixWith0x(identityPrefixStringified), res.IdentityPrefix)

	reqBody := service.RegisterEventIdentityRequest{
		EventTriggerDefinitionHex: triggerDefinitionResp.EventTriggerDefinition,
		IdentityPrefix:            identityPrefixStringified,
		Ttl:                       10,
	}

	registerJSON, err := json.Marshal(reqBody)
	s.Require().NoError(err)

	registerResponse := s.registerEventIdentityRequest(registerJSON, http.StatusOK)
	registerResult := registerResponse["message"]
	s.Require().NotEmpty(registerResult.TxHash)
	s.Require().Equal(res.IdentityPrefix, registerResult.IdentityPrefix)
	s.Require().Equal(res.Eon, registerResult.Eon)

	var expirationResp usecase.GetEventTriggerExpirationBlockResponse
	for i := 0; i < 15; i++ {
		status, resp, _ := s.getEventTriggerExpirationBlockRequestWithStatus(registerResult.Eon, registerResult.IdentityPrefix)
		if status == http.StatusOK && resp.ExpirationBlockNumber > 0 {
			expirationResp = resp
			break
		}
		time.Sleep(2 * time.Second)
	}

	s.Require().Greater(expirationResp.ExpirationBlockNumber, uint64(0))
}

func (s *TestShutterService) TestGetEventDecryptionKeyInvalidIdentity() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	errResp := s.getEventDecryptionKeyRequestError("0x11", http.StatusBadRequest)
	s.Require().Equal("identity should be of length 32", errResp.Description)
}

func (s *TestShutterService) compileEventTriggerDefinitionRequest(jsonData []byte, statusCode int) usecase.EventTriggerDefinitionResponse {
	url := "/api/event/compile_trigger_definition"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var response usecase.EventTriggerDefinitionResponse
	err = json.Unmarshal(body, &response)
	s.Require().NoError(err)

	return response
}

func (s *TestShutterService) compileEventTriggerDefinitionRequestError(jsonData []byte, statusCode int) string {
	url := "/api/event/compile_trigger_definition"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	return string(body)
}

func (s *TestShutterService) getEventDataForEncryptionRequest(triggerDefinition string, identityPrefix string) map[string]usecase.GetDataForEncryptionResponse {
	query := fmt.Sprintf("?triggerDefinition=%s&identityPrefix=%s", triggerDefinition, identityPrefix)
	url := "/api/event/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	return dataForEncryptionResponse
}

func (s *TestShutterService) getEventDataForEncryptionRequestError(identityPrefix string, statusCode int) httpError.Http {
	query := fmt.Sprintf("?identityPrefix=%s", identityPrefix)
	url := "/api/event/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	return errorResponse
}

func (s *TestShutterService) registerEventIdentityRequest(jsonData []byte, statusCode int) map[string]usecase.RegisterIdentityResponse {
	url := "/api/event/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var registerResponse map[string]usecase.RegisterIdentityResponse
	err = json.Unmarshal(body, &registerResponse)
	s.Require().NoError(err)

	return registerResponse
}

func (s *TestShutterService) getEventTriggerExpirationBlockRequestWithStatus(eon uint64, identityPrefix string) (int, usecase.GetEventTriggerExpirationBlockResponse, httpError.Http) {
	query := fmt.Sprintf("?eon=%d&identityPrefix=%s", eon, identityPrefix)
	url := "/api/event/get_trigger_expiration_block" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	if recorder.Code == http.StatusOK {
		var response map[string]usecase.GetEventTriggerExpirationBlockResponse
		err = json.Unmarshal(body, &response)
		s.Require().NoError(err)
		return recorder.Code, response["message"], httpError.Http{}
	}

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	return recorder.Code, usecase.GetEventTriggerExpirationBlockResponse{}, errorResponse
}

func (s *TestShutterService) getEventDecryptionKeyRequestError(identity string, statusCode int) httpError.Http {
	query := fmt.Sprintf("?identity=%s", identity)
	url := "/api/event/get_decryption_key" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(statusCode, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	return errorResponse
}
