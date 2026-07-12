package voter

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/relayer/message"
	"github.com/stretchr/testify/require"
)

func TestSubmitSignatureRejectsNilDestinationChainID(t *testing.T) {
	v := &EVMVoter{}

	err := v.SubmitSignature(&message.Message{}, nil, &common.Address{})

	require.EqualError(t, err, "destination chain ID is nil")
}

func TestSubmitSignatureRejectsNilDestinationBridgeAddress(t *testing.T) {
	v := &EVMVoter{}

	err := v.SubmitSignature(&message.Message{}, big.NewInt(56), nil)

	require.EqualError(t, err, "destination bridge address is nil")
}
