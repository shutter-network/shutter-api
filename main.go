package main

import (
	"context"
	"crypto/rand"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/address"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/env"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/keys"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
	shutterServiceCommon "github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/common/database"
	_ "github.com/shutter-network/shutter-service-api/docs"
	"github.com/shutter-network/shutter-service-api/internal/router"
	"github.com/shutter-network/shutter-service-api/watcher"
)

// @title			Shutter service API
// @description	Shutter Service API is an encryption and decryption service that allows clients to register decryption triggers for specific encrypted messages. These triggers are invoked at a future time, eventually releasing the keys needed to decrypt the messages. Clients can specify the exact timestamp at which the trigger should release the decryption keys.
func main() {
	port := os.Getenv("SERVER_PORT")

	ctx := context.Background()
	dbURL := database.GetDBURL()
	db, err := database.NewDB(ctx, dbURL)
	if err != nil {
		log.Info().Err(err).Msg("failed to initialize db")
		return
	}

	// Run migrations
	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if err := database.RunMigrations(ctx, dbURL, migrationsPath); err != nil {
		log.Err(err).Msg("failed to run database migrations")
		return
	}

	rpc_url := os.Getenv("RPC_URL")
	client, err := ethclient.Dial(rpc_url)
	if err != nil {
		log.Err(err).Msg("failed to initialize rpc client")
		return
	}

	shutterRegistryContractAddressStringified := os.Getenv("SHUTTER_REGISTRY_CONTRACT_ADDRESS")
	shutterRegistryContractAddress := common.HexToAddress(shutterRegistryContractAddressStringified)

	keyBroadcastContractAddressStringified := os.Getenv("KEY_BROADCAST_CONTRACT_ADDRESS")
	keyBroadcastContractAddress := common.HexToAddress(keyBroadcastContractAddressStringified)

	keyperSetManagerContractAddressStringified := os.Getenv("KEYPER_SET_MANAGER_CONTRACT_ADDRESS")
	keyperSetManagerContractAddress := common.HexToAddress(keyperSetManagerContractAddressStringified)

	contract, err := shutterServiceCommon.NewContract(client, shutterRegistryContractAddress, keyperSetManagerContractAddress, keyBroadcastContractAddress)
	if err != nil {
		log.Err(err).Msg("failed to instantiate shutter contracts")
		return
	}

	keyperHTTPUrl := os.Getenv("KEYPER_HTTP_URL")

	signingKey, err := crypto.HexToECDSA(os.Getenv("SIGNING_KEY"))
	if err != nil {
		log.Err(err).Msg("failed to parse signing key")
	}

	p2pConfig := p2p.Config{}
	p2pkey, err := keys.GenerateLibp2pPrivate(rand.Reader)
	if err != nil {
		log.Err(err).Msg("failed to generate p2p key")
		panic(err)
	}
	p2pConfig.P2PKey = p2pkey

	bootstrapAddressesStringified := os.Getenv("P2P_BOOTSTRAP_ADDRESSES")
	if bootstrapAddressesStringified == "" {
		panic("bootstrap addresses not provided in the env")
	}
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
	p2pEnviroment, err := strconv.ParseInt(os.Getenv("P2P_ENVIRONMENT"), 10, 0)
	if err != nil {
		log.Err(err).Msg("failed to parse p2p environment")
		panic(err)
	}
	p2pConfig.Environment = env.Environment(p2pEnviroment)
	p2pConfig.DiscoveryNamespace = os.Getenv("P2P_DISCOVERY_NAMESPACE")

	config, err := shutterServiceCommon.NewConfig(keyperHTTPUrl, signingKey, &p2pConfig)
	if err != nil {
		log.Err(err).Msg("unable to parse keyper http url")
		return
	}
	app := router.NewRouter(db, contract, client, config)
	watcher := watcher.NewWatcher(config, db)
	group, deferFn := service.RunBackground(ctx, watcher)
	defer deferFn()
	go func() {
		if err := group.Wait(); err != nil {
			log.Err(err).Msg("watcher service failed")
		}
	}()
	app.Run("0.0.0.0:" + port)
}
