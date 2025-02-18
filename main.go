package main

import (
	"context"
	shutterAPICommon "github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/common/database"
	"github.com/shutter-network/shutter-api/internal/router"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
)

// @title			Shutter API
// @description	Shutter API is an encryption and decryption API that allows clients to register decryption triggers for specific encrypted messages. These triggers are invoked at a future time, eventually releasing the keys needed to decrypt the messages. Clients can specify the exact timestamp at which the trigger should release the decryption keys.
func main() {
	port := os.Getenv("SERVER_PORT")

	ctx := context.Background()
	dbURL := database.GetDBURL()
	db, err := database.NewDB(ctx, dbURL)
	if err != nil {
		log.Info().Err(err).Msg("failed to initialize db")
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

	contract, err := shutterAPICommon.NewContract(client, shutterRegistryContractAddress, keyperSetManagerContractAddress, keyBroadcastContractAddress)
	if err != nil {
		log.Err(err).Msg("failed to instantiate shutter contracts")
		return
	}

	keyperHTTPUrl := os.Getenv("KEYPER_HTTP_URL")

	signingKey, err := crypto.HexToECDSA(os.Getenv("SIGNING_KEY"))
	if err != nil {
		log.Err(err).Msg("failed to parse signing key")
	}

	config, err := shutterAPICommon.NewConfig(keyperHTTPUrl, signingKey)
	if err != nil {
		log.Err(err).Msg("unable to parse keyper http url")
		return
	}
	app := router.NewRouter(db, contract, client, config)
	app.Run("0.0.0.0:" + port)
}