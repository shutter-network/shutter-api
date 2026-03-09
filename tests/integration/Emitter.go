// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package integration

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// EmitterMetaData contains all meta data concerning the Emitter contract.
var EmitterMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"five\",\"type\":\"bytes\"}],\"name\":\"Five\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"}],\"name\":\"Four\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"five\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"six\",\"type\":\"bytes\"}],\"name\":\"Six\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"newValue\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"ValueChanged\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"five\",\"type\":\"bytes\"}],\"name\":\"emitFive\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"}],\"name\":\"emitFour\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"four\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"five\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"six\",\"type\":\"bytes\"}],\"name\":\"emitSix\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"emitValueChanged\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x6080604052348015600e575f5ffd5b506106f68061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c80636995a2d91461004e5780638cc5e8921461006a578063c7e4ffb814610086578063ea4c0dda146100a2575b5f5ffd5b61006860048036038101906100639190610343565b6100be565b005b610084600480360381019061007f91906103f2565b610101565b005b6100a0600480360381019061009b9190610472565b610141565b005b6100bc60048036038101906100b79190610533565b610187565b005b8284867f2778059b9d45e2cd0df03a27bbe3e688dfc48aa15a729c42f39dcd986ebd446185856040516100f29291906105be565b60405180910390a45050505050565b8183857fd82c9bd67140e94b50e0a62e800c51428267b0cd733573daaafad26b62c05afb8460405161013391906105f3565b60405180910390a450505050565b8385877fccb223cead4ef048ba1febef8eb3147707f88cb86ed2687fe5d3506ad1a3f65b86868660405161017793929190610622565b60405180910390a4505050505050565b807f2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee3061995039038260056040516101b891906106a7565b60405180910390a250565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6101e6816101d4565b81146101f0575f5ffd5b50565b5f81359050610201816101dd565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b6102558261020f565b810181811067ffffffffffffffff821117156102745761027361021f565b5b80604052505050565b5f6102866101c3565b9050610292828261024c565b919050565b5f67ffffffffffffffff8211156102b1576102b061021f565b5b6102ba8261020f565b9050602081019050919050565b828183375f83830152505050565b5f6102e76102e284610297565b61027d565b9050828152602081018484840111156103035761030261020b565b5b61030e8482856102c7565b509392505050565b5f82601f83011261032a57610329610207565b5b813561033a8482602086016102d5565b91505092915050565b5f5f5f5f5f60a0868803121561035c5761035b6101cc565b5b5f610369888289016101f3565b955050602061037a888289016101f3565b945050604061038b888289016101f3565b935050606086013567ffffffffffffffff8111156103ac576103ab6101d0565b5b6103b888828901610316565b925050608086013567ffffffffffffffff8111156103d9576103d86101d0565b5b6103e588828901610316565b9150509295509295909350565b5f5f5f5f6080858703121561040a576104096101cc565b5b5f610417878288016101f3565b9450506020610428878288016101f3565b9350506040610439878288016101f3565b925050606085013567ffffffffffffffff81111561045a576104596101d0565b5b61046687828801610316565b91505092959194509250565b5f5f5f5f5f5f60c0878903121561048c5761048b6101cc565b5b5f61049989828a016101f3565b96505060206104aa89828a016101f3565b95505060406104bb89828a016101f3565b945050606087013567ffffffffffffffff8111156104dc576104db6101d0565b5b6104e889828a01610316565b93505060806104f989828a016101f3565b92505060a087013567ffffffffffffffff81111561051a576105196101d0565b5b61052689828a01610316565b9150509295509295509295565b5f60208284031215610548576105476101cc565b5b5f610555848285016101f3565b91505092915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f6105908261055e565b61059a8185610568565b93506105aa818560208601610578565b6105b38161020f565b840191505092915050565b5f6040820190508181035f8301526105d68185610586565b905081810360208301526105ea8184610586565b90509392505050565b5f6020820190508181035f83015261060b8184610586565b905092915050565b61061c816101d4565b82525050565b5f6060820190508181035f83015261063a8186610586565b90506106496020830185610613565b818103604083015261065b8184610586565b9050949350505050565b5f819050919050565b5f819050919050565b5f61069161068c61068784610665565b61066e565b6101d4565b9050919050565b6106a181610677565b82525050565b5f6020820190506106ba5f830184610698565b9291505056fea264697066735822122061d56a74d8e6c7777271ab758dd95820ea6e8f1cea3556cb49ba7ca77961b22e64736f6c634300081c0033",
}

// EmitterABI is the input ABI used to generate the binding from.
// Deprecated: Use EmitterMetaData.ABI instead.
var EmitterABI = EmitterMetaData.ABI

// EmitterBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use EmitterMetaData.Bin instead.
var EmitterBin = EmitterMetaData.Bin

// DeployEmitter deploys a new Ethereum contract, binding an instance of Emitter to it.
func DeployEmitter(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Emitter, error) {
	parsed, err := EmitterMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(EmitterBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Emitter{EmitterCaller: EmitterCaller{contract: contract}, EmitterTransactor: EmitterTransactor{contract: contract}, EmitterFilterer: EmitterFilterer{contract: contract}}, nil
}

// Emitter is an auto generated Go binding around an Ethereum contract.
type Emitter struct {
	EmitterCaller     // Read-only binding to the contract
	EmitterTransactor // Write-only binding to the contract
	EmitterFilterer   // Log filterer for contract events
}

// EmitterCaller is an auto generated read-only Go binding around an Ethereum contract.
type EmitterCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EmitterTransactor is an auto generated write-only Go binding around an Ethereum contract.
type EmitterTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EmitterFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type EmitterFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EmitterSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type EmitterSession struct {
	Contract     *Emitter          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// EmitterCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type EmitterCallerSession struct {
	Contract *EmitterCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// EmitterTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type EmitterTransactorSession struct {
	Contract     *EmitterTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// EmitterRaw is an auto generated low-level Go binding around an Ethereum contract.
type EmitterRaw struct {
	Contract *Emitter // Generic contract binding to access the raw methods on
}

// EmitterCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type EmitterCallerRaw struct {
	Contract *EmitterCaller // Generic read-only contract binding to access the raw methods on
}

// EmitterTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type EmitterTransactorRaw struct {
	Contract *EmitterTransactor // Generic write-only contract binding to access the raw methods on
}

// NewEmitter creates a new instance of Emitter, bound to a specific deployed contract.
func NewEmitter(address common.Address, backend bind.ContractBackend) (*Emitter, error) {
	contract, err := bindEmitter(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Emitter{EmitterCaller: EmitterCaller{contract: contract}, EmitterTransactor: EmitterTransactor{contract: contract}, EmitterFilterer: EmitterFilterer{contract: contract}}, nil
}

// NewEmitterCaller creates a new read-only instance of Emitter, bound to a specific deployed contract.
func NewEmitterCaller(address common.Address, caller bind.ContractCaller) (*EmitterCaller, error) {
	contract, err := bindEmitter(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &EmitterCaller{contract: contract}, nil
}

// NewEmitterTransactor creates a new write-only instance of Emitter, bound to a specific deployed contract.
func NewEmitterTransactor(address common.Address, transactor bind.ContractTransactor) (*EmitterTransactor, error) {
	contract, err := bindEmitter(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &EmitterTransactor{contract: contract}, nil
}

// NewEmitterFilterer creates a new log filterer instance of Emitter, bound to a specific deployed contract.
func NewEmitterFilterer(address common.Address, filterer bind.ContractFilterer) (*EmitterFilterer, error) {
	contract, err := bindEmitter(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &EmitterFilterer{contract: contract}, nil
}

// bindEmitter binds a generic wrapper to an already deployed contract.
func bindEmitter(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := EmitterMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Emitter *EmitterRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Emitter.Contract.EmitterCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Emitter *EmitterRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Emitter.Contract.EmitterTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Emitter *EmitterRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Emitter.Contract.EmitterTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Emitter *EmitterCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Emitter.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Emitter *EmitterTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Emitter.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Emitter *EmitterTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Emitter.Contract.contract.Transact(opts, method, params...)
}

// EmitFive is a paid mutator transaction binding the contract method 0x6995a2d9.
//
// Solidity: function emitFive(uint256 one, uint256 two, uint256 three, bytes four, bytes five) returns()
func (_Emitter *EmitterTransactor) EmitFive(opts *bind.TransactOpts, one *big.Int, two *big.Int, three *big.Int, four []byte, five []byte) (*types.Transaction, error) {
	return _Emitter.contract.Transact(opts, "emitFive", one, two, three, four, five)
}

// EmitFive is a paid mutator transaction binding the contract method 0x6995a2d9.
//
// Solidity: function emitFive(uint256 one, uint256 two, uint256 three, bytes four, bytes five) returns()
func (_Emitter *EmitterSession) EmitFive(one *big.Int, two *big.Int, three *big.Int, four []byte, five []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFive(&_Emitter.TransactOpts, one, two, three, four, five)
}

// EmitFive is a paid mutator transaction binding the contract method 0x6995a2d9.
//
// Solidity: function emitFive(uint256 one, uint256 two, uint256 three, bytes four, bytes five) returns()
func (_Emitter *EmitterTransactorSession) EmitFive(one *big.Int, two *big.Int, three *big.Int, four []byte, five []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFive(&_Emitter.TransactOpts, one, two, three, four, five)
}

// EmitFour is a paid mutator transaction binding the contract method 0x8cc5e892.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, bytes four) returns()
func (_Emitter *EmitterTransactor) EmitFour(opts *bind.TransactOpts, one *big.Int, two *big.Int, three *big.Int, four []byte) (*types.Transaction, error) {
	return _Emitter.contract.Transact(opts, "emitFour", one, two, three, four)
}

// EmitFour is a paid mutator transaction binding the contract method 0x8cc5e892.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, bytes four) returns()
func (_Emitter *EmitterSession) EmitFour(one *big.Int, two *big.Int, three *big.Int, four []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFour(&_Emitter.TransactOpts, one, two, three, four)
}

// EmitFour is a paid mutator transaction binding the contract method 0x8cc5e892.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, bytes four) returns()
func (_Emitter *EmitterTransactorSession) EmitFour(one *big.Int, two *big.Int, three *big.Int, four []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFour(&_Emitter.TransactOpts, one, two, three, four)
}

// EmitSix is a paid mutator transaction binding the contract method 0xc7e4ffb8.
//
// Solidity: function emitSix(uint256 one, uint256 two, uint256 three, bytes four, uint256 five, bytes six) returns()
func (_Emitter *EmitterTransactor) EmitSix(opts *bind.TransactOpts, one *big.Int, two *big.Int, three *big.Int, four []byte, five *big.Int, six []byte) (*types.Transaction, error) {
	return _Emitter.contract.Transact(opts, "emitSix", one, two, three, four, five, six)
}

// EmitSix is a paid mutator transaction binding the contract method 0xc7e4ffb8.
//
// Solidity: function emitSix(uint256 one, uint256 two, uint256 three, bytes four, uint256 five, bytes six) returns()
func (_Emitter *EmitterSession) EmitSix(one *big.Int, two *big.Int, three *big.Int, four []byte, five *big.Int, six []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitSix(&_Emitter.TransactOpts, one, two, three, four, five, six)
}

// EmitSix is a paid mutator transaction binding the contract method 0xc7e4ffb8.
//
// Solidity: function emitSix(uint256 one, uint256 two, uint256 three, bytes four, uint256 five, bytes six) returns()
func (_Emitter *EmitterTransactorSession) EmitSix(one *big.Int, two *big.Int, three *big.Int, four []byte, five *big.Int, six []byte) (*types.Transaction, error) {
	return _Emitter.Contract.EmitSix(&_Emitter.TransactOpts, one, two, three, four, five, six)
}

// EmitValueChanged is a paid mutator transaction binding the contract method 0xea4c0dda.
//
// Solidity: function emitValueChanged(uint256 value) returns()
func (_Emitter *EmitterTransactor) EmitValueChanged(opts *bind.TransactOpts, value *big.Int) (*types.Transaction, error) {
	return _Emitter.contract.Transact(opts, "emitValueChanged", value)
}

// EmitValueChanged is a paid mutator transaction binding the contract method 0xea4c0dda.
//
// Solidity: function emitValueChanged(uint256 value) returns()
func (_Emitter *EmitterSession) EmitValueChanged(value *big.Int) (*types.Transaction, error) {
	return _Emitter.Contract.EmitValueChanged(&_Emitter.TransactOpts, value)
}

// EmitValueChanged is a paid mutator transaction binding the contract method 0xea4c0dda.
//
// Solidity: function emitValueChanged(uint256 value) returns()
func (_Emitter *EmitterTransactorSession) EmitValueChanged(value *big.Int) (*types.Transaction, error) {
	return _Emitter.Contract.EmitValueChanged(&_Emitter.TransactOpts, value)
}

// EmitterFiveIterator is returned from FilterFive and is used to iterate over the raw logs and unpacked data for Five events raised by the Emitter contract.
type EmitterFiveIterator struct {
	Event *EmitterFive // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EmitterFiveIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EmitterFive)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EmitterFive)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EmitterFiveIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EmitterFiveIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EmitterFive represents a Five event raised by the Emitter contract.
type EmitterFive struct {
	One   *big.Int
	Two   *big.Int
	Three *big.Int
	Four  []byte
	Five  []byte
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterFive is a free log retrieval operation binding the contract event 0x2778059b9d45e2cd0df03a27bbe3e688dfc48aa15a729c42f39dcd986ebd4461.
//
// Solidity: event Five(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, bytes five)
func (_Emitter *EmitterFilterer) FilterFive(opts *bind.FilterOpts, one []*big.Int, two []*big.Int, three []*big.Int) (*EmitterFiveIterator, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.FilterLogs(opts, "Five", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return &EmitterFiveIterator{contract: _Emitter.contract, event: "Five", logs: logs, sub: sub}, nil
}

// WatchFive is a free log subscription operation binding the contract event 0x2778059b9d45e2cd0df03a27bbe3e688dfc48aa15a729c42f39dcd986ebd4461.
//
// Solidity: event Five(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, bytes five)
func (_Emitter *EmitterFilterer) WatchFive(opts *bind.WatchOpts, sink chan<- *EmitterFive, one []*big.Int, two []*big.Int, three []*big.Int) (event.Subscription, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.WatchLogs(opts, "Five", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EmitterFive)
				if err := _Emitter.contract.UnpackLog(event, "Five", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFive is a log parse operation binding the contract event 0x2778059b9d45e2cd0df03a27bbe3e688dfc48aa15a729c42f39dcd986ebd4461.
//
// Solidity: event Five(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, bytes five)
func (_Emitter *EmitterFilterer) ParseFive(log types.Log) (*EmitterFive, error) {
	event := new(EmitterFive)
	if err := _Emitter.contract.UnpackLog(event, "Five", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EmitterFourIterator is returned from FilterFour and is used to iterate over the raw logs and unpacked data for Four events raised by the Emitter contract.
type EmitterFourIterator struct {
	Event *EmitterFour // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EmitterFourIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EmitterFour)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EmitterFour)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EmitterFourIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EmitterFourIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EmitterFour represents a Four event raised by the Emitter contract.
type EmitterFour struct {
	One   *big.Int
	Two   *big.Int
	Three *big.Int
	Four  []byte
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterFour is a free log retrieval operation binding the contract event 0xd82c9bd67140e94b50e0a62e800c51428267b0cd733573daaafad26b62c05afb.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four)
func (_Emitter *EmitterFilterer) FilterFour(opts *bind.FilterOpts, one []*big.Int, two []*big.Int, three []*big.Int) (*EmitterFourIterator, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.FilterLogs(opts, "Four", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return &EmitterFourIterator{contract: _Emitter.contract, event: "Four", logs: logs, sub: sub}, nil
}

// WatchFour is a free log subscription operation binding the contract event 0xd82c9bd67140e94b50e0a62e800c51428267b0cd733573daaafad26b62c05afb.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four)
func (_Emitter *EmitterFilterer) WatchFour(opts *bind.WatchOpts, sink chan<- *EmitterFour, one []*big.Int, two []*big.Int, three []*big.Int) (event.Subscription, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.WatchLogs(opts, "Four", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EmitterFour)
				if err := _Emitter.contract.UnpackLog(event, "Four", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFour is a log parse operation binding the contract event 0xd82c9bd67140e94b50e0a62e800c51428267b0cd733573daaafad26b62c05afb.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four)
func (_Emitter *EmitterFilterer) ParseFour(log types.Log) (*EmitterFour, error) {
	event := new(EmitterFour)
	if err := _Emitter.contract.UnpackLog(event, "Four", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EmitterSixIterator is returned from FilterSix and is used to iterate over the raw logs and unpacked data for Six events raised by the Emitter contract.
type EmitterSixIterator struct {
	Event *EmitterSix // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EmitterSixIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EmitterSix)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EmitterSix)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EmitterSixIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EmitterSixIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EmitterSix represents a Six event raised by the Emitter contract.
type EmitterSix struct {
	One   *big.Int
	Two   *big.Int
	Three *big.Int
	Four  []byte
	Five  *big.Int
	Six   []byte
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterSix is a free log retrieval operation binding the contract event 0xccb223cead4ef048ba1febef8eb3147707f88cb86ed2687fe5d3506ad1a3f65b.
//
// Solidity: event Six(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, uint256 five, bytes six)
func (_Emitter *EmitterFilterer) FilterSix(opts *bind.FilterOpts, one []*big.Int, two []*big.Int, three []*big.Int) (*EmitterSixIterator, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.FilterLogs(opts, "Six", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return &EmitterSixIterator{contract: _Emitter.contract, event: "Six", logs: logs, sub: sub}, nil
}

// WatchSix is a free log subscription operation binding the contract event 0xccb223cead4ef048ba1febef8eb3147707f88cb86ed2687fe5d3506ad1a3f65b.
//
// Solidity: event Six(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, uint256 five, bytes six)
func (_Emitter *EmitterFilterer) WatchSix(opts *bind.WatchOpts, sink chan<- *EmitterSix, one []*big.Int, two []*big.Int, three []*big.Int) (event.Subscription, error) {

	var oneRule []interface{}
	for _, oneItem := range one {
		oneRule = append(oneRule, oneItem)
	}
	var twoRule []interface{}
	for _, twoItem := range two {
		twoRule = append(twoRule, twoItem)
	}
	var threeRule []interface{}
	for _, threeItem := range three {
		threeRule = append(threeRule, threeItem)
	}

	logs, sub, err := _Emitter.contract.WatchLogs(opts, "Six", oneRule, twoRule, threeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EmitterSix)
				if err := _Emitter.contract.UnpackLog(event, "Six", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSix is a log parse operation binding the contract event 0xccb223cead4ef048ba1febef8eb3147707f88cb86ed2687fe5d3506ad1a3f65b.
//
// Solidity: event Six(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, uint256 five, bytes six)
func (_Emitter *EmitterFilterer) ParseSix(log types.Log) (*EmitterSix, error) {
	event := new(EmitterSix)
	if err := _Emitter.contract.UnpackLog(event, "Six", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EmitterValueChangedIterator is returned from FilterValueChanged and is used to iterate over the raw logs and unpacked data for ValueChanged events raised by the Emitter contract.
type EmitterValueChangedIterator struct {
	Event *EmitterValueChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *EmitterValueChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EmitterValueChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(EmitterValueChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *EmitterValueChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EmitterValueChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EmitterValueChanged represents a ValueChanged event raised by the Emitter contract.
type EmitterValueChanged struct {
	NewValue *big.Int
	Value    *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterValueChanged is a free log retrieval operation binding the contract event 0x2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee30619950390382.
//
// Solidity: event ValueChanged(uint256 indexed newValue, uint256 value)
func (_Emitter *EmitterFilterer) FilterValueChanged(opts *bind.FilterOpts, newValue []*big.Int) (*EmitterValueChangedIterator, error) {

	var newValueRule []interface{}
	for _, newValueItem := range newValue {
		newValueRule = append(newValueRule, newValueItem)
	}

	logs, sub, err := _Emitter.contract.FilterLogs(opts, "ValueChanged", newValueRule)
	if err != nil {
		return nil, err
	}
	return &EmitterValueChangedIterator{contract: _Emitter.contract, event: "ValueChanged", logs: logs, sub: sub}, nil
}

// WatchValueChanged is a free log subscription operation binding the contract event 0x2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee30619950390382.
//
// Solidity: event ValueChanged(uint256 indexed newValue, uint256 value)
func (_Emitter *EmitterFilterer) WatchValueChanged(opts *bind.WatchOpts, sink chan<- *EmitterValueChanged, newValue []*big.Int) (event.Subscription, error) {

	var newValueRule []interface{}
	for _, newValueItem := range newValue {
		newValueRule = append(newValueRule, newValueItem)
	}

	logs, sub, err := _Emitter.contract.WatchLogs(opts, "ValueChanged", newValueRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EmitterValueChanged)
				if err := _Emitter.contract.UnpackLog(event, "ValueChanged", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseValueChanged is a log parse operation binding the contract event 0x2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee30619950390382.
//
// Solidity: event ValueChanged(uint256 indexed newValue, uint256 value)
func (_Emitter *EmitterFilterer) ParseValueChanged(log types.Log) (*EmitterValueChanged, error) {
	event := new(EmitterValueChanged)
	if err := _Emitter.contract.UnpackLog(event, "ValueChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
