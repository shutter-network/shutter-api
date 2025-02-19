package tests

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"math/rand"
	"strings"

	"github.com/shutter-network/shutter/shlib/shcrypto"
	"github.com/stretchr/testify/mock"
)

var msg = []byte("please hide this message")

func (s *TestShutterService) TestDecryptionCommitmentNotFound() {
	ctx := context.Background()
	eon := rand.Int63()

	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)

	eonPublicKey, _, _ := s.makeKeys(identity)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)
	epochID := shcrypto.ComputeEpochID(identity)
	encryptedCommitment := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)
	encrypedCommitmentBytes := encryptedCommitment.Marshal()

	timestamp := 1732885990
	s.shutterRegistryContract.
		On("Registrations", mock.AnythingOfType("*bind.CallOpts"), [32]byte(identity)).
		Return(struct {
			Eon       uint64
			Timestamp uint64
		}{
			Eon:       uint64(eon),
			Timestamp: uint64(timestamp),
		}, nil).
		Once()

	identityStringified := hex.EncodeToString(identity)
	encryptedCommitmentStringified := hex.EncodeToString(encrypedCommitmentBytes)
	_, err = s.cryptoUsecase.DecryptCommitment(ctx, encryptedCommitmentStringified, identityStringified)
	s.Require().Error(err)
}

func (s *TestShutterService) TestDecryptionCommitment() {
	ctx := context.Background()
	eon := rand.Int63()

	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)

	eonPublicKey, decryptionKey, epochID := s.makeKeys(identity)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)
	commitment := []byte(msg)
	encryptedCommitment := shcrypto.Encrypt(commitment, eonPublicKey, epochID, sigma)

	encrypedCommitmentBytes := encryptedCommitment.Marshal()

	timestamp := 1732885990

	s.shutterRegistryContract.
		On("Registrations", mock.AnythingOfType("*bind.CallOpts"), [32]byte(identity)).
		Return(struct {
			Eon       uint64
			Timestamp uint64
		}{
			Eon:       uint64(eon),
			Timestamp: uint64(timestamp),
		}, nil).
		Once()

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, identity, decryptionKey.Marshal())
	s.Require().NoError(err)

	identityStringified := hex.EncodeToString(identity)
	encryptedCommitmentStringified := "0x" + hex.EncodeToString(encrypedCommitmentBytes)
	decryptedCommitment, err := s.cryptoUsecase.DecryptCommitment(ctx, encryptedCommitmentStringified, identityStringified)
	s.Require().Nil(err)
	dec, err := hex.DecodeString(strings.TrimPrefix(decryptedCommitment, "0x"))
	s.Require().Nil(err)
	s.Require().Equal(dec, msg)
}
