package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	shutterAPICommon "github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/common/database"
	"github.com/shutter-network/shutter-api/internal/router"
	"github.com/shutter-network/shutter-api/metrics"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/address"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/env"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/encodeable/keys"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/metricsserver"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/p2p"
	_ "github.com/shutter-network/shutter-api/docs"
	"github.com/shutter-network/shutter-api/watcher"
)

// @title			Shutter API
// @description	Shutter API is an encryption and decryption API that allows clients to register decryption triggers for specific encrypted messages. These triggers are invoked at a future time, eventually releasing the keys needed to decrypt the messages. Clients can specify the exact timestamp at which the trigger should release the decryption keys.
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description (Optional): Type "Bearer" followed by a space and your API key.

func main() {
	port := os.Getenv("SERVER_PORT")

	// Get log level from environment variable, default to "info"
	levelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	level := zerolog.InfoLevel

	switch levelStr {
	case "trace":
		level = zerolog.TraceLevel
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	case "fatal":
		level = zerolog.FatalLevel
	case "panic":
		level = zerolog.PanicLevel
	}

	zerolog.SetGlobalLevel(level)

	ctx, cancel := context.WithCancel(context.Background())
	dbURL := database.GetDBURL()
	db, err := database.NewDB(ctx, dbURL)
	if err != nil {
		log.Info().Err(err).Msg("failed to initialize db")
		return
	}

	// Run migrations
	migrationsPath := "./migrations"
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

	metricsEnabledStr := os.Getenv("METRICS_ENABLED")
	metricsEnabled, err := strconv.ParseBool(metricsEnabledStr)
	if err != nil {
		log.Err(err).Msg("failed to get METRICS_ENABLED env")
		metricsEnabled = false
	}

	metricsHost := os.Getenv("METRICS_HOST")
	if metricsHost == "" {
		metricsHost = "[::]"
	}

	metricsPortStr := os.Getenv("METRICS_PORT")
	metricsPort, err := strconv.ParseUint(metricsPortStr, 10, 0)
	if err != nil || metricsPort == 0 {
		log.Err(err).Msg("failed to get METRICS_PORT env")
		metricsPort = 4000
	}

	metricsConfig := &metricsserver.MetricsConfig{
		Enabled: metricsEnabled,
		Host:    metricsHost,
		Port:    uint16(metricsPort),
	}
	var metricsServer *metricsserver.MetricsServer

	if metricsEnabled {
		metrics.InitMetrics()
		metricsServer = metricsserver.New(metricsConfig)
	}

	shutterRegistryContractAddressStringified := os.Getenv("SHUTTER_REGISTRY_CONTRACT_ADDRESS")
	shutterRegistryContractAddress := common.HexToAddress(shutterRegistryContractAddressStringified)

	shutterEventRegistryContractAddressStringified := os.Getenv("SHUTTER_EVENT_REGISTRY_CONTRACT_ADDRESS")
	shutterEventRegistryContractAddress := common.HexToAddress(shutterEventRegistryContractAddressStringified)

	keyBroadcastContractAddressStringified := os.Getenv("KEY_BROADCAST_CONTRACT_ADDRESS")
	keyBroadcastContractAddress := common.HexToAddress(keyBroadcastContractAddressStringified)

	keyperSetManagerContractAddressStringified := os.Getenv("KEYPER_SET_MANAGER_CONTRACT_ADDRESS")
	keyperSetManagerContractAddress := common.HexToAddress(keyperSetManagerContractAddressStringified)

	contract, err := shutterAPICommon.NewContract(client, shutterRegistryContractAddress, shutterEventRegistryContractAddress, keyperSetManagerContractAddress, keyBroadcastContractAddress)
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
	var p2pKey keys.Libp2pPrivate
	p2pKeyString := os.Getenv("P2P_KEY")
	if p2pKeyString == "" {
		panic("P2P key not provided in the env")
	}
	if err := p2pKey.UnmarshalText([]byte(p2pKeyString)); err != nil {
		panic("error unmarshalling P2P key")
	}
	p2pConfig.P2PKey = &p2pKey

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

	p2pPort := os.Getenv("P2P_PORT")
	if p2pPort == "" {
		p2pPort = "23003"
	}

	p2pConfig.ListenAddresses = []*address.P2PAddress{
		address.MustP2PAddress("/ip4/0.0.0.0/tcp/" + p2pPort),
		address.MustP2PAddress("/ip4/0.0.0.0/udp/" + p2pPort + "/quic-v1"),
		address.MustP2PAddress("/ip4/0.0.0.0/udp/" + p2pPort + "/quic-v1/webtransport"),
		address.MustP2PAddress("/ip6/::/tcp/" + p2pPort),
		address.MustP2PAddress("/ip6/::/udp/" + p2pPort + "/quic-v1"),
		address.MustP2PAddress("/ip6/::/udp/" + p2pPort + "/quic-v1/webtransport"),
	}
	p2pEnviroment, err := strconv.ParseInt(os.Getenv("P2P_ENVIRONMENT"), 10, 0)
	if err != nil {
		log.Err(err).Msg("failed to parse p2p environment")
		panic(err)
	}
	p2pConfig.Environment = env.Environment(p2pEnviroment)
	p2pConfig.DiscoveryNamespace = os.Getenv("P2P_DISCOVERY_NAMESPACE")

	config, err := shutterAPICommon.NewConfig(keyperHTTPUrl, signingKey, &p2pConfig)
	if err != nil {
		log.Err(err).Msg("unable to parse keyper http url")
		return
	}
	app := router.NewRouter(ctx, db, contract, client, config)
	watcher := watcher.NewWatcher(config, db)
	group, deferFn := service.RunBackground(ctx, watcher)
	defer deferFn()

	if metricsConfig.Enabled {
		group, deferFn := service.RunBackground(ctx, metricsServer)
		defer deferFn()
		go func() {
			if err := group.Wait(); err != nil {
				log.Err(err).Msg("metrics server failed")
			}
		}()
	}

	go func() {
		if err := group.Wait(); err != nil {
			log.Err(err).Msg("watcher service failed")
			cancel()
			return
		}
	}()

	// Run the server with context
	if err := router.RunWithContext(ctx, cancel, app, "0.0.0.0:"+port); err != nil {
		log.Err(err).Msg("server shutdown error")
	}
}
