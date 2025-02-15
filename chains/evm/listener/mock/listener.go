// Code generated by MockGen. DO NOT EDIT.
// Source: ./chains/evm/listener/listener.go

// Package mock_listener is a generated GoMock package.
package mock_listener

import (
	context "context"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmclient"
	big "math/big"
	reflect "reflect"

	"github.com/meterio/chainbridge-core/relayer/message"
	types "github.com/meterio/chainbridge-core/types"
	common "github.com/ethereum/go-ethereum/common"
	gomock "github.com/golang/mock/gomock"
)

// MockChainClient is a mock of ChainClient interface.
type MockChainClient struct {
	ctrl     *gomock.Controller
	recorder *MockChainClientMockRecorder
}

// MockChainClientMockRecorder is the mock recorder for MockChainClient.
type MockChainClientMockRecorder struct {
	mock *MockChainClient
}

// NewMockChainClient creates a new mock instance.
func NewMockChainClient(ctrl *gomock.Controller) *MockChainClient {
	mock := &MockChainClient{ctrl: ctrl}
	mock.recorder = &MockChainClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockChainClient) EXPECT() *MockChainClientMockRecorder {
	return m.recorder
}

// CallContract mocks base method.
func (m *MockChainClient) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CallContract", ctx, callArgs, blockNumber)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CallContract indicates an expected call of CallContract.
func (mr *MockChainClientMockRecorder) CallContract(ctx, callArgs, blockNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CallContract", reflect.TypeOf((*MockChainClient)(nil).CallContract), ctx, callArgs, blockNumber)
}

// FetchDepositLogs mocks base method.
func (m *MockChainClient) FetchDepositLogs(ctx context.Context, address common.Address, startBlock, endBlock *big.Int) ([]*evmclient.DepositLogs, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FetchDepositLogs", ctx, address, startBlock, endBlock)
	ret0, _ := ret[0].([]*evmclient.DepositLogs)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FetchDepositLogs indicates an expected call of FetchDepositLogs.
func (mr *MockChainClientMockRecorder) FetchDepositLogs(ctx, address, startBlock, endBlock interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FetchDepositLogs", reflect.TypeOf((*MockChainClient)(nil).FetchDepositLogs), ctx, address, startBlock, endBlock)
}

// LatestBlock mocks base method.
func (m *MockChainClient) LatestBlock() (*big.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LatestBlock")
	ret0, _ := ret[0].(*big.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LatestBlock indicates an expected call of LatestBlock.
func (mr *MockChainClientMockRecorder) LatestBlock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LatestBlock", reflect.TypeOf((*MockChainClient)(nil).LatestBlock))
}

// MockEventHandler is a mock of EventHandler interface.
type MockEventHandler struct {
	ctrl     *gomock.Controller
	recorder *MockEventHandlerMockRecorder
}

// MockEventHandlerMockRecorder is the mock recorder for MockEventHandler.
type MockEventHandlerMockRecorder struct {
	mock *MockEventHandler
}

// NewMockEventHandler creates a new mock instance.
func NewMockEventHandler(ctrl *gomock.Controller) *MockEventHandler {
	mock := &MockEventHandler{ctrl: ctrl}
	mock.recorder = &MockEventHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEventHandler) EXPECT() *MockEventHandlerMockRecorder {
	return m.recorder
}

func (m *MockEventHandler) SignaturesContract() signatures.SignaturesContract {
	return signatures.SignaturesContract{}
}

// HandleEvent mocks base method.
func (m *MockEventHandler) HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleEvent", sourceID, destID, nonce, resourceID, calldata, handlerResponse)
	ret0, _ := ret[0].(*message.Message)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HandleEvent indicates an expected call of HandleEvent.
func (mr *MockEventHandlerMockRecorder) HandleEvent(sourceID, destID, nonce, resourceID, calldata, handlerResponse interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleEvent", reflect.TypeOf((*MockEventHandler)(nil).HandleEvent), sourceID, destID, nonce, resourceID, calldata, handlerResponse)
}
