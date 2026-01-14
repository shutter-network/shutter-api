package tests

import (
	"context"
	"encoding/hex"
	"math/big"
	"math/rand"

	cryptorand "crypto/rand"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter/shlib/shcrypto"
	blst "github.com/supranational/blst/bindings/go"
	"gotest.tools/assert"
)

func bigToScalar(i *big.Int) *blst.Scalar {
	max256Bit := new(big.Int).Lsh(big.NewInt(1), 256)
	normalized := new(big.Int).Mod(i, max256Bit)

	b := make([]byte, 32)
	normalized.FillBytes(b)
	s := new(blst.Scalar)
	s.FromBEndian(b)
	return s
}

func generateP2(i *big.Int) *blst.P2Affine {
	s := bigToScalar(i)
	return blst.P2Generator().Mult(s).ToAffine()
}

func (s *TestShutterService) makeKeys(identity []byte) (*shcrypto.EonPublicKey, *shcrypto.EpochSecretKey, *shcrypto.EpochID) {
	s.T().Helper()
	n := 3
	threshold := uint64(2)
	epochID := shcrypto.ComputeEpochID(identity)

	ps := []*shcrypto.Polynomial{}
	gammas := []*shcrypto.Gammas{}
	for i := 0; i < n; i++ {
		p, err := shcrypto.RandomPolynomial(cryptorand.Reader, threshold-1)
		assert.NilError(s.T(), err)
		ps = append(ps, p)
		gammas = append(gammas, p.Gammas())
	}

	eonSecretKeyShares := []*shcrypto.EonSecretKeyShare{}
	epochSecretKeyShares := []*shcrypto.EpochSecretKeyShare{}
	eonSecretKey := big.NewInt(0)
	for i := 0; i < n; i++ {
		eonSecretKey.Add(eonSecretKey, ps[i].Eval(big.NewInt(0)))

		ss := []*big.Int{}
		for j := 0; j < n; j++ {
			s := ps[j].EvalForKeyper(i)
			ss = append(ss, s)
		}
		eonSecretKeyShares = append(eonSecretKeyShares, shcrypto.ComputeEonSecretKeyShare(ss))
		_ = shcrypto.ComputeEonPublicKeyShare(i, gammas)
		epochSecretKeyShares = append(epochSecretKeyShares, shcrypto.ComputeEpochSecretKeyShare(eonSecretKeyShares[i], epochID))
	}
	eonPublicKey := shcrypto.ComputeEonPublicKey(gammas)
	eonPublicKeyExp := (*shcrypto.EonPublicKey)(generateP2(eonSecretKey))
	assert.Assert(s.T(), eonPublicKey.Equal(eonPublicKeyExp))
	epochSecretKey, err := shcrypto.ComputeEpochSecretKey(
		[]int{0, 1},
		[]*shcrypto.EpochSecretKeyShare{epochSecretKeyShares[0], epochSecretKeyShares[1]},
		threshold)
	assert.NilError(s.T(), err)

	return eonPublicKey, epochSecretKey, epochID
}

func (s *TestShutterService) TestGetDataForEncryption() {
	ctx := context.Background()
	_, _, sender, err := generateRandomETHAccount()
	s.Require().NoError(err)
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	identity := common.ComputeIdentity(identityPrefix, ethCommon.HexToAddress(sender))
	blockNumber := rand.Uint64()

	eon := rand.Uint64()

	eonPublicKey, _, epochID := s.makeKeys(identity)

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

	data, err := s.cryptoUsecase.GetDataForEncryption(ctx, sender, identityPrefixStringified, "")
	s.Require().Nil(err)

	s.Require().Equal(data.Eon, eon)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identity)), data.Identity)
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(identityPrefix)), data.IdentityPrefix)
	s.Require().Equal(data.EonKey, common.PrefixWith0x(hex.EncodeToString(eonPublicKey.Marshal())))
	s.Require().Equal(common.PrefixWith0x(hex.EncodeToString(epochID.Marshal())), data.EpochID)
}

func (s *TestShutterService) TestGetDataForEncryptionInvalidSender() {
	ctx := context.Background()
	sender := "0xWrongAddy"
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	identity := common.ComputeIdentity(identityPrefix, ethCommon.HexToAddress(sender))
	blockNumber := rand.Uint64()
	eon := rand.Uint64()

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

	_, err = s.cryptoUsecase.GetDataForEncryption(ctx, sender, identityPrefixStringified, "")
	s.Require().Error(err)
}