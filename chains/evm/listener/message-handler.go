package listener

import (
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/chains/evm/voter/proposal"
	"github.com/ChainSafe/chainbridge-core/config/chain"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"math/big"
)

type MessageHandlerFunc func(m *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error)

// NewEVMMessageHandler creates an instance of EVMMessageHandler that contains
// message handler functions for converting deposit message into a chain specific
// proposal
func NewEVMMessageHandler(config chain.EVMConfig, airDropErc20Contract erc20.ERC20Contract, t transactor.Transactor) *EVMMessageHandler {
	return &EVMMessageHandler{
		cfg:                  config,
		airDropErc20Contract: airDropErc20Contract,
		t:                    t,
	}
}

type EVMMessageHandler struct {
	//bridgeContract bridge.BridgeContract
	//handlers       map[common.Address]MessageHandlerFunc

	airDropErc20Contract erc20.ERC20Contract
	cfg                  chain.EVMConfig
	t                    transactor.Transactor
}

func (w *EVMMessageHandler) CheckAndExecuteAirDropNative(m message.Message) {
	ok, _, to, amount := w.shouldAirDropNative(m)
	if ok == false {
		return
	}

	gasLimit := uint64(21000)

	var airData []byte
	w.t.Transact(to, airData, transactor.TransactOptions{Value: amount, GasLimit: gasLimit})

	return
}

func (w *EVMMessageHandler) CheckAndExecuteAirDropErc20(m message.Message) {
	ok, _, _, to, amount := w.shouldAirDropErc20(m)
	if ok == false {
		return
	}

	w.airDropErc20Contract.Transfer(*to, amount, transactor.TransactOptions{})

	return
}

func (w *EVMMessageHandler) CheckAndExecuteAirDrop(m message.Message) {
	w.CheckAndExecuteAirDropNative(m)
	w.CheckAndExecuteAirDropErc20(m)
}

// airDrop executes the proposal
func (w *EVMMessageHandler) shouldAirDropNative(m message.Message) (bool, uint8, *common.Address, *big.Int) {
	// "{Source:1 Destination:2 Type:FungibleTransfer DepositNonce:11 ResourceId:[0 0 0 0 0 0 0 0 0 0 0 34 142 187 238 153 156 106 122 215 74 97 48 232 27 18 249 254 35 123 163 1] Payload:[[248 176 161 14 71 0 0] [2 5 194 216 98 202 5 16 16 105 139 105 181 66 120 203 175 148 92 11]]}"
	// all information we have here: source. dest, transfer type(erc20, generic), resourceId, If it is ERC20, amount, recipient
	transferType := m.Type

	// only ERC20 allow to airdrop
	if transferType != message.FungibleTransfer {
		return false, 0, nil, nil
	}

	// The default airDropAmount should be configured..
	if w.cfg.AirDropAmount.Sign() == 0 {
		return false, 0, nil, nil
	}

	// yes, let do the airDrop
	// now decode the payload.
	source := m.Source
	dest := m.Destination
	nonce := m.DepositNonce
	resourceId := m.ResourceId
	amount := new(big.Int).SetBytes(m.Payload[0].([]byte))
	recipient := common.BytesToAddress(m.Payload[1].([]byte))

	log.Info().Uint8("source", source).Uint8("dest", dest).Str("type", string(transferType)).Uint64("nonce", nonce).Str("amount", amount.String()).Hex("recipient", recipient[:]).Hex("resourceId", resourceId[:]).Msg("AirDrop Native...")
	log.Debug().Uint8("dest", dest).Hex("recipient", recipient[:]).Str("amount", w.cfg.AirDropAmount.String()).Msg("airdrop parameters")

	return true, dest, &recipient, w.cfg.AirDropAmount
}

// airDrop executes the proposal
func (w *EVMMessageHandler) shouldAirDropErc20(m message.Message) (bool, uint8, *common.Address, *common.Address, *big.Int) {
	// "{Source:1 Destination:2 Type:FungibleTransfer DepositNonce:11 ResourceId:[0 0 0 0 0 0 0 0 0 0 0 34 142 187 238 153 156 106 122 215 74 97 48 232 27 18 249 254 35 123 163 1] Payload:[[248 176 161 14 71 0 0] [2 5 194 216 98 202 5 16 16 105 139 105 181 66 120 203 175 148 92 11]]}"
	// all information we have here: source. dest, transfer type(erc20, generic), resourceId, If it is ERC20, amount, recipient
	transferType := m.Type

	// only ERC20 allow to airdrop
	if transferType != message.FungibleTransfer {
		return false, 0, nil, nil, nil
	}

	// Check the configuration
	if (w.cfg.AirDropErc20Amount.Sign() == 0) || (w.cfg.AirDropErc20Contract == util.ZeroAddress) {
		return false, 0, nil, nil, nil
	}

	// yes, let do the airDrop
	// now decode the payload.
	source := m.Source
	dest := m.Destination
	nonce := m.DepositNonce
	resourceId := m.ResourceId
	amount := new(big.Int).SetBytes(m.Payload[0].([]byte))
	recipient := common.BytesToAddress(m.Payload[1].([]byte))
	log.Info().Uint8("source", source).Uint8("dest", dest).Str("type", string(transferType)).Uint64("nonce", nonce).Str("amount", amount.String()).Hex("recipient", recipient[:]).Hex("resourceId", resourceId[:]).Msg("AirDrop Erc20...")

	erc20Contract := w.cfg.AirDropErc20Contract
	// source from ethereum main, the fee is configured amount
	// otherwise is fixed amount 0.5 (5e17) token
	var erc20Amount *big.Int
	if source == 1 {
		erc20Amount = w.cfg.AirDropErc20Amount
	} else {
		erc20Amount = big.NewInt(5e17)
	}

	log.Debug().Uint8("dest", dest).Hex("erc20Contract", erc20Contract[:]).Hex("recipient", recipient[:]).Str("amount", erc20Amount.String()).Msg("airdrop parameters")
	return true, dest, &erc20Contract, &recipient, erc20Amount
}
