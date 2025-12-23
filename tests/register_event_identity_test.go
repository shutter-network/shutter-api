package tests

import (
	"context"
	"encoding/hex"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/shutter-network/shutter-api/common"
	"github.com/stretchr/testify/mock"
)

func (s *TestShutterService) TestRegisterEventIdentity() {
	ctx := context.Background()
	ttl := uint64(100)
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()

	eon := rand.Uint64()

	// Hardcoded valid event trigger definition
	eventTriggerDefinitionHex := "0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"
	eventTriggerDefinitionBytes, err := hexutil.Decode(eventTriggerDefinitionHex)
	s.Require().NoError(err)

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)

	identity := common.ComputeEventIdentity(identityPrefix[:], newSigner.From, eventTriggerDefinitionBytes)

	eonPublicKey, _, _ := s.makeKeys(identity)

	randomTx := generateRandomTransaction()

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	s.ethClient.
		On("ChainID", ctx).
		Return(big.NewInt(GnosisMainnetChainID), nil).
		Once()

	s.shutterEventRegistryContract.
		On("Register", mock.Anything, eon, [32]byte(identityPrefix), eventTriggerDefinitionBytes, ttl).
		Return(randomTx, nil).
		Once()

	data, err := s.cryptoUsecase.RegisterEventIdentity(ctx, eventTriggerDefinitionHex, identityPrefixStringified, ttl)
	s.Require().Nil(err)

	s.Require().Equal(data.Eon, eon)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identity)), data.Identity)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identityPrefix)), data.IdentityPrefix)
	s.Require().Equal(data.EonKey, common.PrefixWith0x(hex.EncodeToString(eonPublicKey.Marshal())))
	s.Require().Equal(randomTx.Hash().Hex(), data.TxHash)
}

func (s *TestShutterService) TestRegisterEventIdentity_InvalidIdentityPrefix() {
	ctx := context.Background()
	ttl := uint64(100)
	eventTriggerDefinitionHex := "0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"

	// Test with invalid identity prefix length
	invalidIdentityPrefix := "0x1234" // Too short

	_, err := s.cryptoUsecase.RegisterEventIdentity(ctx, eventTriggerDefinitionHex, invalidIdentityPrefix, ttl)
	s.Require().NotNil(err)

	// Verify the exact error message
	s.Require().Equal("identity prefix should be of byte length 32", err.Description)
	s.Require().Equal(400, err.StatusCode)
}

func (s *TestShutterService) TestRegisterEventIdentity_InvalidEventTriggerDefinition() {
	ctx := context.Background()
	ttl := uint64(100)
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()
	eon := rand.Uint64()

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)

	// Test with invalid hex string
	invalidEventTriggerDefinitionHex := "0xinvalid"
	// Note: Since the endpoint will fail at hex decoding, identity computation never happens
	// But we still need to set up the mock. Use a dummy valid trigger definition for mock setup.
	dummyTriggerBytes, _ := hexutil.Decode("0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402")
	identity := common.ComputeEventIdentity(identityPrefix[:], newSigner.From, dummyTriggerBytes)

	eonPublicKey, _, _ := s.makeKeys(identity)

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	s.ethClient.
		On("ChainID", ctx).
		Return(big.NewInt(GnosisMainnetChainID), nil).
		Once()

	_, httpErr := s.cryptoUsecase.RegisterEventIdentity(ctx, invalidEventTriggerDefinitionHex, identityPrefixStringified, ttl)
	s.Require().NotNil(httpErr)

	// Verify the exact error message
	s.Require().Equal("could not decode event trigger definition", httpErr.Description)
	s.Require().Equal(400, httpErr.StatusCode)
}

func (s *TestShutterService) TestRegisterEventIdentity_TriggerDefinitionWithout0xPrefix() {
	ctx := context.Background()
	ttl := uint64(100)
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()
	eon := rand.Uint64()

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)

	eventTriggerDefinitionHexWithoutPrefix := "01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"
	// Decode the trigger definition to compute identity (endpoint will decode it with 0x prefix)
	eventTriggerDefinitionBytes, err := hexutil.Decode("0x" + eventTriggerDefinitionHexWithoutPrefix)
	s.Require().NoError(err)
	identity := common.ComputeEventIdentity(identityPrefix[:], newSigner.From, eventTriggerDefinitionBytes)

	eonPublicKey, _, _ := s.makeKeys(identity)

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	s.ethClient.
		On("ChainID", ctx).
		Return(big.NewInt(GnosisMainnetChainID), nil).
		Once()

	_, httpErr := s.cryptoUsecase.RegisterEventIdentity(ctx, eventTriggerDefinitionHexWithoutPrefix, identityPrefixStringified, ttl)
	s.Require().NotNil(httpErr)

	// Verify the exact error message
	s.Require().Equal("could not decode event trigger definition", httpErr.Description)
	s.Require().Equal(400, httpErr.StatusCode)
}

func (s *TestShutterService) TestRegisterEventIdentity_ZeroBytesEventTriggerDefinition() {
	ctx := context.Background()
	ttl := uint64(100)
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()
	eon := rand.Uint64()

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)

	// Create a zero-filled hex string (128 hex chars = 64 bytes)
	zeroEventTriggerDefinitionHex := "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	// Decode the zero bytes to compute identity (endpoint will decode it before computing identity)
	zeroBytes, err := hexutil.Decode(zeroEventTriggerDefinitionHex)
	s.Require().NoError(err)
	identity := common.ComputeEventIdentity(identityPrefix[:], newSigner.From, zeroBytes)

	eonPublicKey, _, _ := s.makeKeys(identity)

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	s.ethClient.
		On("ChainID", ctx).
		Return(big.NewInt(GnosisMainnetChainID), nil).
		Once()

	_, httpErr := s.cryptoUsecase.RegisterEventIdentity(ctx, zeroEventTriggerDefinitionHex, identityPrefixStringified, ttl)
	s.Require().NotNil(httpErr)

	// Verify the exact error message
	s.Require().Equal("could not parse event trigger definition", httpErr.Description)
	s.Require().Equal(400, httpErr.StatusCode)
}

func (s *TestShutterService) TestRegisterEventIdentity_EmptyIdentityPrefix() {
	ctx := context.Background()
	ttl := uint64(100)
	blockNumber := rand.Uint64()
	eon := rand.Uint64()

	// Hardcoded valid event trigger definition
	eventTriggerDefinitionHex := "0x01f86694953a0425accee2e05f22e78999c595ed2ee7183cf84fe480e205a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efe401e205a0000000000000000000000000812a6755975485c6e340f97de6790b34a94d1430c404c20402"
	eventTriggerDefinitionBytes, err := hexutil.Decode(eventTriggerDefinitionHex)
	s.Require().NoError(err)

	// Generate a random identity prefix that will be used to compute identity
	// Note: The function will generate its own random prefix, but we need to set up mocks
	// So we'll use a predictable prefix for the identity computation in mocks
	randomIdentityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)
	// Compute identity with event trigger definition to match the new implementation
	identity := common.ComputeEventIdentity(randomIdentityPrefix[:], newSigner.From, eventTriggerDefinitionBytes)

	eonPublicKey, _, _ := s.makeKeys(identity)

	randomTx := generateRandomTransaction()

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	s.ethClient.
		On("ChainID", ctx).
		Return(big.NewInt(GnosisMainnetChainID), nil).
		Once()

	// Mock will be called with the generated identity prefix (we can't predict it, so use mock.MatchedBy)
	s.shutterEventRegistryContract.
		On("Register", mock.Anything, eon, mock.MatchedBy(func(prefix [32]byte) bool {
			return true
		}), eventTriggerDefinitionBytes, ttl).
		Return(randomTx, nil).
		Once()

	data, err := s.cryptoUsecase.RegisterEventIdentity(ctx, eventTriggerDefinitionHex, "", ttl)
	s.Require().Nil(err)

	s.Require().Equal(data.Eon, eon)
	s.Require().NotEqual(data.IdentityPrefix, "")
	s.Require().NotEqual(data.Identity, "")
	s.Require().Equal(data.EonKey, common.PrefixWith0x(hex.EncodeToString(eonPublicKey.Marshal())))
	s.Require().Equal(randomTx.Hash().Hex(), data.TxHash)
}
