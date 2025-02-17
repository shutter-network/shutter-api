package tests

import (
	"context"
	"encoding/hex"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/shutter-network/shutter-api/common"
	"github.com/stretchr/testify/mock"
)

func (s *TestShutterService) TestRegisterIdentity() {
	ctx := context.Background()
	decryptionTimestamp := time.Now().Add(1 * time.Hour).Unix()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()

	eon := rand.Uint64()

	newSigner, err := bind.NewKeyedTransactorWithChainID(s.config.SigningKey, big.NewInt(GnosisMainnetChainID))
	s.Require().NoError(err)
	identity := common.ComputeIdentity(identityPrefix[:], newSigner.From)

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

	s.shutterRegistryContract.
		On("Register", mock.Anything, eon, [32]byte(identityPrefix), uint64(decryptionTimestamp)).
		Return(randomTx, nil).
		Once()

	data, err := s.cryptoUsecase.RegisterIdentity(ctx, uint64(decryptionTimestamp), identityPrefixStringified)
	s.Require().Nil(err)

	s.Require().Equal(data.Eon, eon)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identity)), data.Identity)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identityPrefix)), data.IdentityPrefix)
	s.Require().Equal(data.EonKey, common.PrefixWith0x(hex.EncodeToString(eonPublicKey.Marshal())))
	s.Require().Equal(randomTx.Hash().Hex(), data.TxHash)
}

func generateRandomTransaction() *types.Transaction {
	nonce := rand.Uint64()
	randomBigInt := big.NewInt(rand.Int63())
	to := ethCommon.BigToAddress(randomBigInt)
	value := randomBigInt
	gasPrice := big.NewInt(1e9)
	gasLimit := uint64(21000)

	// Random data
	data, _ := generateRandomBytes(20)
	// Create a transaction
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
	return tx
}