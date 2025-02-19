package integration

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"crypto/rand"
	cryptoRand "crypto/rand"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/address"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/env"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/keys"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/common/database"
	"github.com/shutter-network/shutter-api/internal/data"
	"github.com/shutter-network/shutter-api/internal/router"
	"github.com/shutter-network/shutter-api/watcher"
	"github.com/stretchr/testify/suite"
)

type TestShutterService struct {
	suite.Suite
	db         *pgxpool.Pool
	dbQuery    *data.Queries
	router     *gin.Engine
	config     *common.Config
	ethClient  *ethclient.Client
	contract   *common.Contract
	testServer *httptest.Server
}

func (s *TestShutterService) SetupSuite() {
	ctx := context.Background()
	var err error
	dbURL := os.Getenv("DB_URL")
	s.db, err = database.NewDB(ctx, dbURL)
	s.Require().NoError(err)

	s.dbQuery = data.New(s.db)
	signingKey, err := crypto.HexToECDSA(os.Getenv("SIGNING_KEY"))
	s.Require().NoError(err)

	keyperHTTPUrl := os.Getenv("KEYPER_HTTP_URL")
	p2pConfig := p2p.Config{}
	p2pkey, err := keys.GenerateLibp2pPrivate(rand.Reader)
	s.Require().NoError(err)
	p2pConfig.P2PKey = p2pkey

	bootstrapAddressesStringified := os.Getenv("P2P_BOOTSTRAP_ADDRESSES")
	s.Assert().NotEmpty(bootstrapAddressesStringified)
	bootstrapAddresses := strings.Split(bootstrapAddressesStringified, ",")

	bootstrapP2PAddresses := make([]*address.P2PAddress, len(bootstrapAddresses))

	for i, addr := range bootstrapAddresses {
		bootstrapP2PAddresses[i] = address.MustP2PAddress(addr)
	}
	p2pConfig.CustomBootstrapAddresses = bootstrapP2PAddresses
	p2pConfig.ListenAddresses = []*address.P2PAddress{
		address.MustP2PAddress("/ip4/0.0.0.0/tcp/23003"),
		address.MustP2PAddress("/ip4/0.0.0.0/udp/23003/quic-v1"),
		address.MustP2PAddress("/ip4/0.0.0.0/udp/23003/quic-v1/webtransport"),
		address.MustP2PAddress("/ip6/::/tcp/23003"),
		address.MustP2PAddress("/ip6/::/udp/23003/quic-v1"),
		address.MustP2PAddress("/ip6/::/udp/23003/quic-v1/webtransport"),
	}
	p2pConfig.Environment = env.Environment(0)
	p2pConfig.DiscoveryNamespace = os.Getenv("P2P_DISCOVERY_NAMESPACE")

	s.config, err = common.NewConfig(keyperHTTPUrl, signingKey, &p2pConfig)
	s.Require().NoError(err)

	rpc_url := os.Getenv("RPC_URL")
	s.ethClient, err = ethclient.Dial(rpc_url)
	s.Require().NoError(err)

	shutterRegistryContractAddressStringified := os.Getenv("SHUTTER_REGISTRY_CONTRACT_ADDRESS")
	shutterRegistryContractAddress := ethCommon.HexToAddress(shutterRegistryContractAddressStringified)

	keyBroadcastContractAddressStringified := os.Getenv("KEY_BROADCAST_CONTRACT_ADDRESS")
	keyBroadcastContractAddress := ethCommon.HexToAddress(keyBroadcastContractAddressStringified)

	keyperSetManagerContractAddressStringified := os.Getenv("KEYPER_SET_MANAGER_CONTRACT_ADDRESS")
	keyperSetManagerContractAddress := ethCommon.HexToAddress(keyperSetManagerContractAddressStringified)

	s.contract, err = common.NewContract(s.ethClient, shutterRegistryContractAddress, keyperSetManagerContractAddress, keyBroadcastContractAddress)
	s.Require().NoError(err)

	migrationsPath := "../../migrations"
	s.Require().NoError(database.RunMigrations(ctx, dbURL, migrationsPath))

	watcher := watcher.NewWatcher(s.config, s.db)
	group, deferFn := service.RunBackground(ctx, watcher)
	defer deferFn()
	go func() {
		s.Require().NoError(group.Wait())
	}()
	s.router = router.NewRouter(s.db, s.contract, s.ethClient, s.config)
	s.testServer = httptest.NewServer(s.router)
}

func TestShutterServiceSuite(t *testing.T) {
	suite.Run(t, new(TestShutterService))
}

func (s *TestShutterService) TearDownSuite() {
	s.db.Close()
	s.testServer.Close()
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := cryptoRand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
