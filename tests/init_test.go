package tests

import (
	"crypto/ecdsa"
	"net/url"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/data"
	"github.com/shutter-network/shutter-api/internal/usecase"
	"github.com/shutter-network/shutter-api/tests/mock"
	"github.com/stretchr/testify/suite"
)

const GnosisMainnetChainID = 100

type TestShutterService struct {
	suite.Suite
	testDB                   *common.TestDatabase
	dbQuery                  *data.Queries
	cryptoUsecase            *usecase.CryptoUsecase
	config                   *common.Config
	shutterRegistryContract  *mock.MockShutterregistry
	keyperSetManagerContract *mock.MockKeyperSetManager
	keyBroadcastContract     *mock.MockKeyBroadcast
	ethClient                *mock.MockEthClient
}

func TestShutterServiceSuite(t *testing.T) {
	suite.Run(t, new(TestShutterService))
}

func (s *TestShutterService) TearDownAllSuite() {
	s.testDB.TearDown()
}

func (s *TestShutterService) SetupSuite() {
	migrationsPath := "./migrations"
	s.testDB = common.SetupTestDatabase(migrationsPath)
	s.dbQuery = data.New(s.testDB.DbInstance)
	privateKey, publicKey, _, err := generateRandomETHAccount()
	s.Require().NoError(err)

	parsedURL, err := url.Parse("https://keyperurl.com")
	if err != nil {
		log.Err(err).Msg("error while parsing url")
		return
	}
	s.config = &common.Config{
		KeyperHTTPURL: parsedURL,
		SigningKey:    privateKey,
		PublicKey:     publicKey,
	}
	s.shutterRegistryContract = new(mock.MockShutterregistry)
	s.keyBroadcastContract = new(mock.MockKeyBroadcast)
	s.keyperSetManagerContract = new(mock.MockKeyperSetManager)
	s.ethClient = new(mock.MockEthClient)
	s.cryptoUsecase = usecase.NewCryptoUsecase(s.testDB.DbInstance, s.shutterRegistryContract, s.keyperSetManagerContract, s.keyBroadcastContract, s.ethClient, s.config)
}

func (s *TestShutterService) BeforeTest(suiteName, testName string) {
	s.shutterRegistryContract.ExpectedCalls = nil
	s.keyBroadcastContract.ExpectedCalls = nil
	s.keyperSetManagerContract.ExpectedCalls = nil
	s.ethClient.ExpectedCalls = nil
}

func generateRandomETHAccount() (*ecdsa.PrivateKey, *ecdsa.PublicKey, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, "", err
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return privateKey, publicKeyECDSA, address, nil
}