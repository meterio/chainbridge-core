// Code generated by MockGen. DO NOT EDIT.
// Source: chains/evm/calls/calls.go

// Package mock_calls is a generated GoMock package.
package mock_calls

import (
	context "context"
	big "math/big"
	reflect "reflect"

	evmclient "github.com/meterio/chainbridge-core/chains/evm/calls/evmclient"
	common "github.com/ethereum/go-ethereum/common"
	types "github.com/ethereum/go-ethereum/core/types"
	gomock "github.com/golang/mock/gomock"
)

// MockContractChecker is a mock of ContractChecker interface.
type MockContractChecker struct {
	ctrl     *gomock.Controller
	recorder *MockContractCheckerMockRecorder
}

// MockContractCheckerMockRecorder is the mock recorder for MockContractChecker.
type MockContractCheckerMockRecorder struct {
	mock *MockContractChecker
}

// NewMockContractChecker creates a new mock instance.
func NewMockContractChecker(ctrl *gomock.Controller) *MockContractChecker {
	mock := &MockContractChecker{ctrl: ctrl}
	mock.recorder = &MockContractCheckerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContractChecker) EXPECT() *MockContractCheckerMockRecorder {
	return m.recorder
}

// CodeAt mocks base method.
func (m *MockContractChecker) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CodeAt", ctx, contract, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CodeAt indicates an expected call of CodeAt.
func (mr *MockContractCheckerMockRecorder) CodeAt(ctx, contract, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CodeAt", reflect.TypeOf((*MockContractChecker)(nil).CodeAt), ctx, contract, blockNumber)
}

// MockContractCaller is a mock of ContractCaller interface.
type MockContractCaller struct {
	ctrl     *gomock.Controller
	recorder *MockContractCallerMockRecorder
}

// MockContractCallerMockRecorder is the mock recorder for MockContractCaller.
type MockContractCallerMockRecorder struct {
	mock *MockContractCaller
}

// NewMockContractCaller creates a new mock instance.
func NewMockContractCaller(ctrl *gomock.Controller) *MockContractCaller {
	mock := &MockContractCaller{ctrl: ctrl}
	mock.recorder = &MockContractCallerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContractCaller) EXPECT() *MockContractCallerMockRecorder {
	return m.recorder
}

// CallContract mocks base method.
func (m *MockContractCaller) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CallContract", ctx, callArgs, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CallContract indicates an expected call of CallContract.
func (mr *MockContractCallerMockRecorder) CallContract(ctx, callArgs, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallContract", reflect.TypeOf((*MockContractCaller)(nil).CallContract), ctx, callArgs, blockNumber)
}

// MockGasPricer is a mock of GasPricer interface.
type MockGasPricer struct {
	ctrl     *gomock.Controller
	recorder *MockGasPricerMockRecorder
}

// MockGasPricerMockRecorder is the mock recorder for MockGasPricer.
type MockGasPricerMockRecorder struct {
	mock *MockGasPricer
}

// NewMockGasPricer creates a new mock instance.
func NewMockGasPricer(ctrl *gomock.Controller) *MockGasPricer {
	mock := &MockGasPricer{ctrl: ctrl}
	mock.recorder = &MockGasPricerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGasPricer) EXPECT() *MockGasPricerMockRecorder {
	return m.recorder
}

// GasPrice mocks base method.
func (m *MockGasPricer) GasPrice() ([]*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GasPrice")
	ret0, _ := ret[0].([]*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GasPrice indicates an expected call of GasPrice.
func (mr *MockGasPricerMockRecorder) GasPrice() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GasPrice", reflect.TypeOf((*MockGasPricer)(nil).GasPrice))
}

// MockClientDispatcher is a mock of ClientDispatcher interface.
type MockClientDispatcher struct {
	ctrl     *gomock.Controller
	recorder *MockClientDispatcherMockRecorder
}

// MockClientDispatcherMockRecorder is the mock recorder for MockClientDispatcher.
type MockClientDispatcherMockRecorder struct {
	mock *MockClientDispatcher
}

// NewMockClientDispatcher creates a new mock instance.
func NewMockClientDispatcher(ctrl *gomock.Controller) *MockClientDispatcher {
	mock := &MockClientDispatcher{ctrl: ctrl}
	mock.recorder = &MockClientDispatcherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientDispatcher) EXPECT() *MockClientDispatcherMockRecorder {
	return m.recorder
}

// From mocks base method.
func (m *MockClientDispatcher) From() common.Address {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "From")
	ret0, _ := ret[0].(common.Address)
	return ret0
}

// From indicates an expected call of From.
func (mr *MockClientDispatcherMockRecorder) From() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "From", reflect.TypeOf((*MockClientDispatcher)(nil).From))
}

// GetTransactionByHash mocks base method.
func (m *MockClientDispatcher) GetTransactionByHash(h common.Hash) (*types.Transaction, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransactionByHash", h)
	ret0, _ := ret[0].(*types.Transaction)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetTransactionByHash indicates an expected call of GetTransactionByHash.
func (mr *MockClientDispatcherMockRecorder) GetTransactionByHash(h interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransactionByHash", reflect.TypeOf((*MockClientDispatcher)(nil).GetTransactionByHash), h)
}

// LockNonce mocks base method.
func (m *MockClientDispatcher) LockNonce() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "LockNonce")
}

// LockNonce indicates an expected call of LockNonce.
func (mr *MockClientDispatcherMockRecorder) LockNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LockNonce", reflect.TypeOf((*MockClientDispatcher)(nil).LockNonce))
}

// SignAndSendTransaction mocks base method.
func (m *MockClientDispatcher) SignAndSendTransaction(ctx context.Context, tx evmclient.CommonTransaction) (common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignAndSendTransaction", ctx, tx)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}


func (mr *MockClientDispatcher) Sign(byteData []byte) ([]byte, error) {
	return []byte{}, nil
}

func (m *MockClientDispatcher) PolygonGasStation() bool {
	return false
}

func (mr *MockClientDispatcherMockRecorder) PolygonGasStation() bool {
	return false
}

func (m *MockContractCallerDispatcher) PolygonGasStation() bool {
	return false
}

// SignAndSendTransaction indicates an expected call of SignAndSendTransaction.
func (mr *MockClientDispatcherMockRecorder) SignAndSendTransaction(ctx, tx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignAndSendTransaction", reflect.TypeOf((*MockClientDispatcher)(nil).SignAndSendTransaction), ctx, tx)
}

// UnlockNonce mocks base method.
func (m *MockClientDispatcher) UnlockNonce() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UnlockNonce")
}

// UnlockNonce indicates an expected call of UnlockNonce.
func (mr *MockClientDispatcherMockRecorder) UnlockNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnlockNonce", reflect.TypeOf((*MockClientDispatcher)(nil).UnlockNonce))
}

// UnsafeIncreaseNonce mocks base method.
func (m *MockClientDispatcher) UnsafeIncreaseNonce() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnsafeIncreaseNonce")
	ret0, _ := ret[0].(error)
	return ret0
}

// UnsafeIncreaseNonce indicates an expected call of UnsafeIncreaseNonce.
func (mr *MockClientDispatcherMockRecorder) UnsafeIncreaseNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnsafeIncreaseNonce", reflect.TypeOf((*MockClientDispatcher)(nil).UnsafeIncreaseNonce))
}

// UnsafeNonce mocks base method.
func (m *MockClientDispatcher) UnsafeNonce() (*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnsafeNonce")
	ret0, _ := ret[0].(*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockClientDispatcher) UpdateNonce() {}

// UnsafeNonce indicates an expected call of UnsafeNonce.
func (mr *MockClientDispatcherMockRecorder) UnsafeNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnsafeNonce", reflect.TypeOf((*MockClientDispatcher)(nil).UnsafeNonce))
}

// WaitAndReturnTxReceipt mocks base method.
func (m *MockClientDispatcher) WaitAndReturnTxReceipt(h common.Hash) (*types.Receipt, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitAndReturnTxReceipt", h)
	ret0, _ := ret[0].(*types.Receipt)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WaitAndReturnTxReceipt indicates an expected call of WaitAndReturnTxReceipt.
func (mr *MockClientDispatcherMockRecorder) WaitAndReturnTxReceipt(h interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitAndReturnTxReceipt", reflect.TypeOf((*MockClientDispatcher)(nil).WaitAndReturnTxReceipt), h)
}

// MockContractCallerDispatcher is a mock of ContractCallerDispatcher interface.
type MockContractCallerDispatcher struct {
	ctrl     *gomock.Controller
	recorder *MockContractCallerDispatcherMockRecorder
}

// MockContractCallerDispatcherMockRecorder is the mock recorder for MockContractCallerDispatcher.
type MockContractCallerDispatcherMockRecorder struct {
	mock *MockContractCallerDispatcher
}

// NewMockContractCallerDispatcher creates a new mock instance.
func NewMockContractCallerDispatcher(ctrl *gomock.Controller) *MockContractCallerDispatcher {
	mock := &MockContractCallerDispatcher{ctrl: ctrl}
	mock.recorder = &MockContractCallerDispatcherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContractCallerDispatcher) EXPECT() *MockContractCallerDispatcherMockRecorder {
	return m.recorder
}

// CallContract mocks base method.
func (m *MockContractCallerDispatcher) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CallContract", ctx, callArgs, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CallContract indicates an expected call of CallContract.
func (mr *MockContractCallerDispatcherMockRecorder) CallContract(ctx, callArgs, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallContract", reflect.TypeOf((*MockContractCallerDispatcher)(nil).CallContract), ctx, callArgs, blockNumber)
}

// CodeAt mocks base method.
func (m *MockContractCallerDispatcher) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CodeAt", ctx, contract, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CodeAt indicates an expected call of CodeAt.
func (mr *MockContractCallerDispatcherMockRecorder) CodeAt(ctx, contract, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CodeAt", reflect.TypeOf((*MockContractCallerDispatcher)(nil).CodeAt), ctx, contract, blockNumber)
}

// From mocks base method.
func (m *MockContractCallerDispatcher) From() common.Address {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "From")
	ret0, _ := ret[0].(common.Address)
	return ret0
}

// From indicates an expected call of From.
func (mr *MockContractCallerDispatcherMockRecorder) From() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "From", reflect.TypeOf((*MockContractCallerDispatcher)(nil).From))
}

// GetTransactionByHash mocks base method.
func (m *MockContractCallerDispatcher) GetTransactionByHash(h common.Hash) (*types.Transaction, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransactionByHash", h)
	ret0, _ := ret[0].(*types.Transaction)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetTransactionByHash indicates an expected call of GetTransactionByHash.
func (mr *MockContractCallerDispatcherMockRecorder) GetTransactionByHash(h interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransactionByHash", reflect.TypeOf((*MockContractCallerDispatcher)(nil).GetTransactionByHash), h)
}

// LockNonce mocks base method.
func (m *MockContractCallerDispatcher) LockNonce() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "LockNonce")
}

// LockNonce indicates an expected call of LockNonce.
func (mr *MockContractCallerDispatcherMockRecorder) LockNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LockNonce", reflect.TypeOf((*MockContractCallerDispatcher)(nil).LockNonce))
}

// SignAndSendTransaction mocks base method.
func (m *MockContractCallerDispatcher) SignAndSendTransaction(ctx context.Context, tx evmclient.CommonTransaction) (common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignAndSendTransaction", ctx, tx)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockContractCallerDispatcher) Sign(byteData []byte) ([]byte, error) {
	return []byte{}, nil
}

// SignAndSendTransaction indicates an expected call of SignAndSendTransaction.
func (mr *MockContractCallerDispatcherMockRecorder) SignAndSendTransaction(ctx, tx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignAndSendTransaction", reflect.TypeOf((*MockContractCallerDispatcher)(nil).SignAndSendTransaction), ctx, tx)
}

// UnlockNonce mocks base method.
func (m *MockContractCallerDispatcher) UnlockNonce() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UnlockNonce")
}

// UnlockNonce indicates an expected call of UnlockNonce.
func (mr *MockContractCallerDispatcherMockRecorder) UnlockNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnlockNonce", reflect.TypeOf((*MockContractCallerDispatcher)(nil).UnlockNonce))
}

// UnsafeIncreaseNonce mocks base method.
func (m *MockContractCallerDispatcher) UnsafeIncreaseNonce() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnsafeIncreaseNonce")
	ret0, _ := ret[0].(error)
	return ret0
}

// UnsafeIncreaseNonce indicates an expected call of UnsafeIncreaseNonce.
func (mr *MockContractCallerDispatcherMockRecorder) UnsafeIncreaseNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnsafeIncreaseNonce", reflect.TypeOf((*MockContractCallerDispatcher)(nil).UnsafeIncreaseNonce))
}

// UnsafeNonce mocks base method.
func (m *MockContractCallerDispatcher) UnsafeNonce() (*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnsafeNonce")
	ret0, _ := ret[0].(*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockContractCallerDispatcher) UpdateNonce() {}

// UnsafeNonce indicates an expected call of UnsafeNonce.
func (mr *MockContractCallerDispatcherMockRecorder) UnsafeNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnsafeNonce", reflect.TypeOf((*MockContractCallerDispatcher)(nil).UnsafeNonce))
}

// WaitAndReturnTxReceipt mocks base method.
func (m *MockContractCallerDispatcher) WaitAndReturnTxReceipt(h common.Hash) (*types.Receipt, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitAndReturnTxReceipt", h)
	ret0, _ := ret[0].(*types.Receipt)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WaitAndReturnTxReceipt indicates an expected call of WaitAndReturnTxReceipt.
func (mr *MockContractCallerDispatcherMockRecorder) WaitAndReturnTxReceipt(h interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitAndReturnTxReceipt", reflect.TypeOf((*MockContractCallerDispatcher)(nil).WaitAndReturnTxReceipt), h)
}

// MockSimulateCaller is a mock of SimulateCaller interface.
type MockSimulateCaller struct {
	ctrl     *gomock.Controller
	recorder *MockSimulateCallerMockRecorder
}

// MockSimulateCallerMockRecorder is the mock recorder for MockSimulateCaller.
type MockSimulateCallerMockRecorder struct {
	mock *MockSimulateCaller
}

// NewMockSimulateCaller creates a new mock instance.
func NewMockSimulateCaller(ctrl *gomock.Controller) *MockSimulateCaller {
	mock := &MockSimulateCaller{ctrl: ctrl}
	mock.recorder = &MockSimulateCallerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSimulateCaller) EXPECT() *MockSimulateCallerMockRecorder {
	return m.recorder
}

// CallContract mocks base method.
func (m *MockSimulateCaller) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CallContract", ctx, callArgs, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CallContract indicates an expected call of CallContract.
func (mr *MockSimulateCallerMockRecorder) CallContract(ctx, callArgs, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallContract", reflect.TypeOf((*MockSimulateCaller)(nil).CallContract), ctx, callArgs, blockNumber)
}

// TransactionByHash mocks base method.
func (m *MockSimulateCaller) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TransactionByHash", ctx, hash)
	ret0, _ := ret[0].(*types.Transaction)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// TransactionByHash indicates an expected call of TransactionByHash.
func (mr *MockSimulateCallerMockRecorder) TransactionByHash(ctx, hash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TransactionByHash", reflect.TypeOf((*MockSimulateCaller)(nil).TransactionByHash), ctx, hash)
}
