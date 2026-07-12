package relayer

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/relayer/message"
	"github.com/meterio/chainbridge-core/types"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

type chainIDTestChain struct {
	domainID        uint8
	relayID         uint8
	chainID         *big.Int
	chainIDErr      error
	bridgeAddress   *common.Address
	voteOnRelayCall int
}

func (c *chainIDTestChain) PollEvents(<-chan struct{}, chan<- error, chan *message.Message) {}
func (c *chainIDTestChain) HandleEvent(uint8, uint8, uint64, types.ResourceID, []byte, []byte) (*message.Message, error) {
	return nil, nil
}
func (c *chainIDTestChain) DomainID() uint8                        { return c.domainID }
func (c *chainIDTestChain) RelayId() uint8                         { return c.relayID }
func (c *chainIDTestChain) ChainID() (*big.Int, error)             { return c.chainID, c.chainIDErr }
func (c *chainIDTestChain) BridgeContractAddress() *common.Address { return c.bridgeAddress }
func (c *chainIDTestChain) SyncBlockLabels() []attribute.KeyValue  { return nil }
func (c *chainIDTestChain) HeadBlockLabels() []attribute.KeyValue  { return nil }
func (c *chainIDTestChain) GetSignatures(*message.Message) ([][]byte, error) {
	return nil, nil
}
func (c *chainIDTestChain) Get(*message.Message) (bool, error) { return false, nil }
func (c *chainIDTestChain) VoteOnDest(*message.Message) error  { return nil }
func (c *chainIDTestChain) VoteOnRelay(*message.Message, *big.Int, *common.Address) error {
	c.voteOnRelayCall++
	return nil
}
func (c *chainIDTestChain) ExecOnDest(*message.Message, [][]byte, *big.Int) error { return nil }
func (c *chainIDTestChain) SignatureSubmit() bool                                 { return false }

func TestRouteDoesNotVoteOnRelayWithoutDestinationChainID(t *testing.T) {
	tests := []struct {
		name       string
		chainID    *big.Int
		chainIDErr error
	}{
		{name: "RPC error", chainIDErr: errors.New("402 Payment Required: Out of CU")},
		{name: "nil result"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &chainIDTestChain{domainID: 1, relayID: 3}
			destination := &chainIDTestChain{domainID: 4, chainID: tt.chainID, chainIDErr: tt.chainIDErr}
			middle := &chainIDTestChain{domainID: 3}
			r := &Relayer{registry: map[uint8]RelayedChain{1: source, 3: middle, 4: destination}}

			r.route(&message.Message{Source: 1, Destination: 4}, make(chan *message.Message))

			require.Zero(t, middle.voteOnRelayCall)
		})
	}
}
