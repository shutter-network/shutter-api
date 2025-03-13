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
	s.Require().Equal(errorResponse.Description, "timestamp not reached yet, decryption key requested too early")
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

	decryptionTimestamp := block.Header().Time + 10
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	s.registerIdentityRequest(jsonData, http.StatusOK)

	time.Sleep(30 * time.Second)

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
	s.Require().Equal(errorResponse.Description, "identity has not been registerd yet")
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
	decryptionTimestamp := block.Header().Time + 10
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	s.registerIdentityRequest(jsonData, http.StatusOK)

	time.Sleep(30 * time.Second)

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
	s.Require().Equal(errorResponse.Description, "decryption timestamp should be in future")
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
	url := "/api/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(statusCode, recorder.Code)
}

func (s *TestShutterService) registerIdentityRequestError(jsonData []byte, statusCode int) httpError.Http {
	url := "/api/register_identity"

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
	url := "/api/get_data_for_encryption" + query

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
	url := "/api/get_decryption_key" + query

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
	url := "/api/get_decryption_key" + query

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
