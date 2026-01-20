package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
)

type MockShutterEventRegistry struct {
	mock.Mock
}

func (m *MockShutterEventRegistry) Register(opts *bind.TransactOpts, eon uint64, identityPrefix [32]byte, triggerDefinition []byte, ttl uint64) (*types.Transaction, error) {
	args := m.Called(opts, eon, identityPrefix, triggerDefinition, ttl)
	return args.Get(0).(*types.Transaction), args.Error(1)
}
