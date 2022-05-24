package voter

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/chains/evm/voter/proposal"
	"github.com/ChainSafe/chainbridge-core/config/chain"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"math/big"
)

type MessageHandlerFunc func(m *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error)

// NewEVMMessageHandler creates an instance of EVMMessageHandler that contains
// message handler functions for converting deposit message into a chain specific
// proposal
func NewEVMMessageHandler(bridgeContract bridge.BridgeContract, config chain.EVMConfig, airDropErc20Contract erc20.ERC20Contract, t transactor.Transactor) *EVMMessageHandler {
	return &EVMMessageHandler{
		bridgeContract:       bridgeContract,
		cfg:                  config,
		airDropErc20Contract: airDropErc20Contract,
		t:                    t,
	}
}

type EVMMessageHandler struct {
	bridgeContract bridge.BridgeContract
	handlers       map[common.Address]MessageHandlerFunc

	airDropErc20Contract erc20.ERC20Contract
	cfg                  chain.EVMConfig
	t                    transactor.Transactor
}

func (mh *EVMMessageHandler) HandleMessage(m *message.Message) (*proposal.Proposal, error) {
	// Matching resource ID with handler.
	addr, err := mh.bridgeContract.GetHandlerAddressForResourceID(m.ResourceId)
	if err != nil {
		return nil, err
	}
	// Based on handler that registered on BridgeContract
	handleMessage, err := mh.MatchAddressWithHandlerFunc(addr)
	if err != nil {
		return nil, err
	}
	log.Info().Str("type", string(m.Type)).Uint8("src", m.Source).Uint8("dst", m.Destination).Uint64("nonce", m.DepositNonce).Str("resourceID", fmt.Sprintf("%x", m.ResourceId)).Msg("Handling new message")
	prop, err := handleMessage(m, addr, *mh.bridgeContract.ContractAddress())
	if err != nil {
		return nil, err
	}

	mh.CheckandExecuteAirDrop(*m)

	return prop, nil
}

func (mh *EVMMessageHandler) MatchAddressWithHandlerFunc(addr common.Address) (MessageHandlerFunc, error) {
	h, ok := mh.handlers[addr]
	if !ok {
		return nil, fmt.Errorf("no corresponding message handler for this address %s exists", addr.Hex())
	}
	return h, nil
}

// RegisterEventHandler registers an message handler by associating a handler function to a specified address
func (mh *EVMMessageHandler) RegisterMessageHandler(address string, handler MessageHandlerFunc) {
	if address == "" {
		return
	}
	if mh.handlers == nil {
		mh.handlers = make(map[common.Address]MessageHandlerFunc)
	}

	log.Info().Msgf("Registered message handler for address %s", address)

	mh.handlers[common.HexToAddress(address)] = handler
}

func ERC20MessageHandler(m *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {
	if len(m.Payload) != 2 {
		return nil, errors.New("malformed payload. Len  of payload should be 2")
	}
	amount, ok := m.Payload[0].([]byte)
	if !ok {
		return nil, errors.New("wrong payloads amount format")
	}
	recipient, ok := m.Payload[1].([]byte)
	if !ok {
		return nil, errors.New("wrong payloads recipient format")
	}
	var data []byte
	data = append(data, common.LeftPadBytes(amount, 32)...) // amount (uint256)
	recipientLen := big.NewInt(int64(len(recipient))).Bytes()
	data = append(data, common.LeftPadBytes(recipientLen, 32)...) // length of recipient (uint256)
	data = append(data, recipient...)                             // recipient ([]byte)
	return proposal.NewProposal(m.Source, m.DepositNonce, m.ResourceId, data, handlerAddr, bridgeAddress), nil
}

func ERC721MessageHandler(msg *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {
	if len(msg.Payload) != 3 {
		return nil, errors.New("malformed payload. Len  of payload should be 3")
	}
	tokenID, ok := msg.Payload[0].([]byte)
	if !ok {
		return nil, errors.New("wrong payloads tokenID format")
	}
	recipient, ok := msg.Payload[1].([]byte)
	if !ok {
		return nil, errors.New("wrong payloads recipient format")
	}
	metadata, ok := msg.Payload[2].([]byte)
	if !ok {
		return nil, errors.New("wrong payloads metadata format")
	}
	data := bytes.Buffer{}
	data.Write(common.LeftPadBytes(tokenID, 32))
	recipientLen := big.NewInt(int64(len(recipient))).Bytes()
	data.Write(common.LeftPadBytes(recipientLen, 32))
	data.Write(recipient)
	metadataLen := big.NewInt(int64(len(metadata))).Bytes()
	data.Write(common.LeftPadBytes(metadataLen, 32))
	data.Write(metadata)
	return proposal.NewProposal(msg.Source, msg.DepositNonce, msg.ResourceId, data.Bytes(), handlerAddr, bridgeAddress), nil
}

func GenericMessageHandler(msg *message.Message, handlerAddr, bridgeAddress common.Address) (*proposal.Proposal, error) {
	if len(msg.Payload) != 1 {
		return nil, errors.New("malformed payload. Len  of payload should be 1")
	}
	metadata, ok := msg.Payload[0].([]byte)
	if !ok {
		return nil, errors.New("unable to convert metadata to []byte")
	}
	data := bytes.Buffer{}
	metadataLen := big.NewInt(int64(len(metadata))).Bytes()
	data.Write(common.LeftPadBytes(metadataLen, 32)) // length of metadata (uint256)
	data.Write(metadata)
	return proposal.NewProposal(msg.Source, msg.DepositNonce, msg.ResourceId, data.Bytes(), handlerAddr, bridgeAddress), nil
}

func (w *EVMMessageHandler) CheckandExecuteAirDropNative(m message.Message) {
	ok, _, to, amount := w.shouldAirDropNative(m)
	if ok == false {
		return
	}

	gasLimit := uint64(21000)

	var airData []byte

	w.t.Transact(to, airData, transactor.TransactOptions{Value: amount, GasLimit: gasLimit})

	return
}

func (w *EVMMessageHandler) CheckandExecuteAirDropErc20(m message.Message) {
	ok, _, _, to, amount := w.shouldAirDropErc20(m)
	if ok == false {
		return
	}

	w.airDropErc20Contract.Transact(to, nil, transactor.TransactOptions{Value: amount})

	return
}

func (w *EVMMessageHandler) CheckandExecuteAirDrop(m message.Message) {
	w.CheckandExecuteAirDropNative(m)
	w.CheckandExecuteAirDropErc20(m)
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
	//source := m.Source
	dest := uint8(m.Destination)
	//nonce := m.DepositNonce
	//resourceId := m.ResourceId
	//amount := new(big.Int).SetBytes(m.Payload[0].([]byte))
	recipient := common.BytesToAddress(m.Payload[1].([]byte))

	log.Info().Msgf(" the airdrop parameters", "dest", dest, "recipent", recipient, "amount", w.cfg.AirDropAmount.String())
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

	zeroAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")

	// Check the configuration
	if (w.cfg.AirDropErc20Amount.Sign() == 0) || (w.cfg.AirDropErc20Contract == zeroAddress) {
		return false, 0, nil, nil, nil
	}

	// yes, let do the airDrop
	// now decode the payload.
	source := m.Source
	dest := uint8(m.Destination)
	//nonce := m.DepositNonce
	//resourceId := m.ResourceId
	//amount := new(big.Int).SetBytes(m.Payload[0].([]byte))
	recipient := common.BytesToAddress(m.Payload[1].([]byte))

	erc20Contract := w.cfg.AirDropErc20Contract
	// source from ethereum main, the fee is configured amount
	// otherwise is fixed amount 0.5 (5e17) token
	var erc20Amount *big.Int
	if source == 1 {
		erc20Amount = w.cfg.AirDropErc20Amount
	} else {
		erc20Amount = big.NewInt(5e17)
	}

	log.Info().Msgf(" the airdrop parameters", "dest", dest, "erc20Contract", &erc20Contract, "recipent", recipient, "amount", erc20Amount.String())
	return true, dest, &erc20Contract, &recipient, erc20Amount
}
