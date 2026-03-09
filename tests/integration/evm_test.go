package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"strings"
	"testing"

	"gotest.tools/assert"

	"github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
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

func AssertMatchManual(t *testing.T, setup Setup, tx *types.Transaction, name string, argument []byte) {
	vLog, err := collectLog(t, setup, tx)
	assert.NilError(t, err, "failure when collecting log: %v", err)

	abi, err := EmitterMetaData.GetAbi()
	assert.NilError(t, err, "error getting ABI: %v", err)
	signature := SigFromABI(abi.Events[name])

	sig, err := sigparser.ParseSignature(signature)
	assert.NilError(t, err, "error parsing signature")

	arg := make([][]byte, 1)
	arg[0] = usecase.Align(argument)
	length := uint64(len(argument)/shs.Word + 1)
	etd := shs.EventTriggerDefinition{
		Contract: setup.contractAddress,
		LogPredicates: []shs.LogPredicate{
			usecase.Topic0(sig),
			{
				LogValueRef: shs.LogValueRef{Offset: 4, Length: length},
				ValuePredicate: shs.ValuePredicate{
					Op:       shs.BytesEq,
					ByteArgs: arg,
				},
			},
		},
	}
	err = etd.Validate()
	assert.NilError(t, err, "validate error")
	match, err := etd.Match(vLog)
	assert.NilError(t, err, "error matching")
	assert.Check(t, match, "did not match")
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
	assert.Equal(t, len(errs), 0, "there were errors compiling: %v", errs)
	match, err := etd.Match(vLog)
	assert.NilError(t, err, "error matching")
	assert.Check(t, match, "did not match")
}

func TestMyEVM(t *testing.T) {
	setup := setupBackend(t)

	// call a function that emits an event
	// event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes memory four);
	four := []byte("aaaada2f51019d7448d33c2d8606653bb54b706d32b35982811639745f42eb720e52da2f51019d7448d33c2d8606653bb54b706d32b35982811639745f42eb720e52")
	dst := make([]byte, 66)
	hex.Decode(dst, []byte(four))
	tx, err := setup.contract.EmitFour(
		setup.auth,
		big.NewInt(41),
		big.NewInt(42),
		big.NewInt(43),
		dst,
	)
	assert.NilError(t, err, "failed to emit event: %v", err)

	hexfour := hex.EncodeToString(dst)
	AssertMatchManual(
		t,
		setup,
		tx,
		"Four",
		dst,
	)
	AssertMatch(
		t,
		setup,
		tx,
		"Four",
		`[{"name": "four", "op": "eq", "bytes": "0x`+hexfour+`"}]`,
	)
}

func TestFive(t *testing.T) {
	setup := setupBackend(t)
	four := []byte("this is the fourth argument")
	five := []byte("this is the fifth argument")
	tx, err := setup.contract.EmitFive(
		setup.auth,
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		four,
		five,
	)
	assert.NilError(t, err, "failed to emit event: %v", err)
	_, err = collectLog(t, setup, tx)
	assert.NilError(t, err, "failure when collecting log: %v", err)
}

func TestSix(t *testing.T) {
	setup := setupBackend(t)
	four := []byte("this is the fourth argument and it is longer than one word")
	six := []byte("this is the sixth argument and it is quite long believe me")
	tx, err := setup.contract.EmitSix(
		setup.auth,
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		four,
		big.NewInt(96),
		six,
	)
	assert.NilError(t, err, "failed to emit event: %v", err)
	_, err = collectLog(t, setup, tx)
	assert.NilError(t, err, "failure when collecting log: %v", err)
}
