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
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"four\",\"type\":\"string\"}],\"name\":\"Four\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"newValue\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"ValueChanged\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"one\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"two\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"three\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"four\",\"type\":\"string\"}],\"name\":\"emitFour\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"emitValueChanged\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x6080604052348015600e575f5ffd5b506104288061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c8063b7047b6714610038578063ea4c0dda14610054575b5f5ffd5b610052600480360381019061004d919061026c565b610070565b005b61006e600480360381019061006991906102ec565b6100b0565b005b8183857f18a815ae98ce3e12272353f42a21c3b1283cf950a001e8b677e79e4ba8ce7fdc846040516100a29190610377565b60405180910390a450505050565b807f2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee3061995039038260056040516100e191906103d9565b60405180910390a250565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b61010f816100fd565b8114610119575f5ffd5b50565b5f8135905061012a81610106565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61017e82610138565b810181811067ffffffffffffffff8211171561019d5761019c610148565b5b80604052505050565b5f6101af6100ec565b90506101bb8282610175565b919050565b5f67ffffffffffffffff8211156101da576101d9610148565b5b6101e382610138565b9050602081019050919050565b828183375f83830152505050565b5f61021061020b846101c0565b6101a6565b90508281526020810184848401111561022c5761022b610134565b5b6102378482856101f0565b509392505050565b5f82601f83011261025357610252610130565b5b81356102638482602086016101fe565b91505092915050565b5f5f5f5f60808587031215610284576102836100f5565b5b5f6102918782880161011c565b94505060206102a28782880161011c565b93505060406102b38782880161011c565b925050606085013567ffffffffffffffff8111156102d4576102d36100f9565b5b6102e08782880161023f565b91505092959194509250565b5f60208284031215610301576103006100f5565b5b5f61030e8482850161011c565b91505092915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f61034982610317565b6103538185610321565b9350610363818560208601610331565b61036c81610138565b840191505092915050565b5f6020820190508181035f83015261038f818461033f565b905092915050565b5f819050919050565b5f819050919050565b5f6103c36103be6103b984610397565b6103a0565b6100fd565b9050919050565b6103d3816103a9565b82525050565b5f6020820190506103ec5f8301846103ca565b9291505056fea2646970667358221220179edb3547c0e643891adb1478550b93450d338769066c55f6b8b4448b71945164736f6c634300081c0033",
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

// EmitFour is a paid mutator transaction binding the contract method 0xb7047b67.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, string four) returns()
func (_Emitter *EmitterTransactor) EmitFour(opts *bind.TransactOpts, one *big.Int, two *big.Int, three *big.Int, four string) (*types.Transaction, error) {
	return _Emitter.contract.Transact(opts, "emitFour", one, two, three, four)
}

// EmitFour is a paid mutator transaction binding the contract method 0xb7047b67.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, string four) returns()
func (_Emitter *EmitterSession) EmitFour(one *big.Int, two *big.Int, three *big.Int, four string) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFour(&_Emitter.TransactOpts, one, two, three, four)
}

// EmitFour is a paid mutator transaction binding the contract method 0xb7047b67.
//
// Solidity: function emitFour(uint256 one, uint256 two, uint256 three, string four) returns()
func (_Emitter *EmitterTransactorSession) EmitFour(one *big.Int, two *big.Int, three *big.Int, four string) (*types.Transaction, error) {
	return _Emitter.Contract.EmitFour(&_Emitter.TransactOpts, one, two, three, four)
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
	Four  string
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterFour is a free log retrieval operation binding the contract event 0x18a815ae98ce3e12272353f42a21c3b1283cf950a001e8b677e79e4ba8ce7fdc.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, string four)
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

// WatchFour is a free log subscription operation binding the contract event 0x18a815ae98ce3e12272353f42a21c3b1283cf950a001e8b677e79e4ba8ce7fdc.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, string four)
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

// ParseFour is a log parse operation binding the contract event 0x18a815ae98ce3e12272353f42a21c3b1283cf950a001e8b677e79e4ba8ce7fdc.
//
// Solidity: event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, string four)
func (_Emitter *EmitterFilterer) ParseFour(log types.Log) (*EmitterFour, error) {
	event := new(EmitterFour)
	if err := _Emitter.contract.UnpackLog(event, "Four", log); err != nil {
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
