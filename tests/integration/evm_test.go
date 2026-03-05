package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"testing"

	"gotest.tools/assert"

	"github.com/ethereum/go-ethereum/accounts/abi"
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

func SigFromABI(evt abi.Event) string {
	var b strings.Builder
	b.WriteString(evt.RawName)
	b.WriteString("(")
	for i, arg := range evt.Inputs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(arg.Type.String())
		b.WriteString(" ")
		if arg.Indexed {
			b.WriteString("indexed ")
		}
		b.WriteString(arg.Name)
	}
	b.WriteString(")")
	return b.String()
}

func AssertMatch(t *testing.T, setup Setup, tx *types.Transaction, name string, argumentsBody string) {
	vLog, err := collectLog(t, setup, tx)
	assert.NilError(t, err, "failure when collecting log: %v", err)

	abi, err := EmitterMetaData.GetAbi()
	assert.NilError(t, err, "error getting ABI: %v", err)
	signature := SigFromABI(abi.Events[name])

	var args []usecase.EventArgument
	err = json.NewDecoder(strings.NewReader(argumentsBody)).Decode(&args)
	assert.NilError(t, err, "invalid json")

	etd, errs := usecase.EventTriggerDefinitionFromRequest(usecase.EventTriggerDefinitionRequest{
		EventSignature:  signature,
		ContractAddress: setup.contractAddress,
		Arguments:       args,
	})
	fmt.Println(etd)
	fmt.Println(vLog)
	assert.Equal(t, len(errs), 0, "there were errors compiling: %v", errs)
	match, err := etd.Match(vLog)
	assert.NilError(t, err, "error matching")
	assert.Check(t, match, "did not match")
}

func TestMyEVM(t *testing.T) {
	setup := setupBackend(t)

	// call a function that emits an event
	// event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, string four);
	four := "Foo"
	tx, err := setup.contract.EmitFour(
		setup.auth,
		big.NewInt(41),
		big.NewInt(42),
		big.NewInt(43),
		four,
	)
	assert.NilError(t, err, "failed to emit event: %v", err)

	hexfour := hex.EncodeToString([]byte(four))
	AssertMatch(
		t,
		setup,
		tx,
		"Four",
		`[{"name": "four", "op": "eq", "bytes": "0x`+hexfour+`"}]`,
	)
}
