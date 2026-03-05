package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"testing"

	"gotest.tools/assert"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/shutter-network/shutter-api/internal/usecase"
)

type Setup struct {
	backend         backends.SimulatedBackend
	auth            *bind.TransactOpts
	contract        *Emitter
	contractAddress common.Address
}

func setupBackend(t *testing.T) Setup {
	t.Helper()

	// create funded genesis account
	privateKey, err := crypto.GenerateKey()
	assert.NilError(t, err, "failed to generate private key %v", err)

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	assert.NilError(t, err, "failed to create transactor %v", err)

	balance := new(big.Int)
	balance.SetString("1000000000000000000000", 10) // 1000 ETH
	alloc := make(types.GenesisAlloc)
	alloc[auth.From] = types.Account{Balance: balance}

	// create SimulatedBackend
	b := simulated.NewBackend(alloc, simulated.WithBlockGasLimit(8000000))
	backend := backends.SimulatedBackend{
		Backend: b,
		Client:  b.Client(),
	}
	// deploy Emitter contract
	// Emitter.go is generated through `make all`
	contractAddress, _, _, err := DeployEmitter(auth, backend)
	assert.NilError(t, err, "failed to deploy contract: %v", err)
	backend.Commit()

	// bind contract
	contract, err := NewEmitter(contractAddress, backend)
	assert.NilError(t, err, "failed to bind contract instance to address %v: %v", contractAddress, err)

	return Setup{
		backend:         backend,
		auth:            auth,
		contract:        contract,
		contractAddress: contractAddress,
	}
}

func collectLog(t *testing.T, setup Setup, tx *types.Transaction) (*types.Log, error) {
	t.Helper()
	// Commit the block to process the transaction
	setup.backend.Commit()

	fmt.Println(tx.Hash())
	// get Receipt for Logs
	receipt, err := setup.backend.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		log.Fatalf("Failed to get receipt: %v", err)
	}
	return receipt.Logs[0], nil
}

func TestMyEVM(t *testing.T) {
	setup := setupBackend(t)

	// call a function that emits an event
	tx, err := setup.contract.EmitValueChanged(setup.auth, big.NewInt(42))
	assert.NilError(t, err, "failed to emit event: %v", err)

	vLog, err := collectLog(t, setup, tx)
	assert.NilError(t, err, "failure when collecting log: %v", err)
	// fmt.Println("Topics:")
	// fmt.Println(vLog)
	// for i, topic := range vLog.Topics {
	// 	fmt.Printf("  Topic %d: %s\n", i, topic.Hex())
	// }
	// fmt.Printf("Data: %s\n", common.Bytes2Hex(vLog.Data))

	argumentsBody := `[{"name": "value", "op": "eq", "number": "5"}]`

	var sig map[string]string
	err = json.NewDecoder(strings.NewReader(EmitterMetaData.ABI)).Decode(&sig)
	assert.NilError(t, err, "invalid json")

	var args []usecase.EventArgument
	err = json.NewDecoder(strings.NewReader(argumentsBody)).Decode(&args)
	assert.NilError(t, err, "invalid json")

	signature := sig["ValueChanged"]

	etdr, errs := usecase.CompileEventTriggerDefinitionInternal(usecase.EventTriggerDefinitionRequest{
		EventSignature:  signature,
		ContractAddress: setup.contractAddress,
		Arguments:       args,
	})
	assert.Equal(t, len(errs), 0, "there were errors compiling")
	etd := etdr.EventTriggerDefinition
	// etd := shs.EventTriggerDefinition{
	// 	Contract: vLog.Address,
	// 	LogPredicates: []shs.LogPredicate{
	// 		{
	// 			LogValueRef: shs.LogValueRef{
	// 				Offset: 1,
	// 				Length: 1,
	// 			},
	// 			ValuePredicate: shs.ValuePredicate{
	// 				Op:       shs.BytesEq,
	// 				ByteArgs: [][]byte{common.BigToHash(big.NewInt(42)).Bytes()},
	// 			},
	// 		},
	// 		{
	// 			LogValueRef: shs.LogValueRef{
	// 				Offset: 4,
	// 				Length: 1,
	// 			},
	// 			ValuePredicate: shs.ValuePredicate{
	// 				Op:      shs.UintEq,
	// 				IntArgs: []*big.Int{big.NewInt(5)},
	// 			},
	// 		},
	// 	},
	// }
	match, err := etd.Match(vLog)
	assert.NilError(t, err, "error matching")
	assert.Check(t, match, "did not match")
}
