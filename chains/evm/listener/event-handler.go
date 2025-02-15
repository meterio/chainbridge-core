package listener

import (
	"errors"
	"math/big"

	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/relayer/message"
	"github.com/meterio/chainbridge-core/types"
	"github.com/rs/zerolog/log"

	"github.com/ethereum/go-ethereum/common"
)

type EventHandlers map[common.Address]EventHandlerFunc
type EventHandlerFunc func(sourceID, destId uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error)

type ETHEventHandler struct {
	bridgeContract bridge.BridgeContract
	eventHandlers  EventHandlers
}

// NewETHEventHandler creates an instance of ETHEventHandler that contains
// handler functions for processing deposit events
func NewETHEventHandler(bridgeContract bridge.BridgeContract) *ETHEventHandler {
	return &ETHEventHandler{
		bridgeContract: bridgeContract,
	}
}

func (e *ETHEventHandler) HandleEvent(sourceID, destID uint8, depositNonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	handlerAddr, err := e.bridgeContract.GetHandlerAddressForResourceID(resourceID)
	if err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			log.Error().Err(err).Msgf("panic occurred while handling deposit")
		}
	}()

	eventHandler, err := e.matchAddressWithHandlerFunc(handlerAddr)
	if err != nil {
		return nil, err
	}

	return eventHandler(sourceID, destID, depositNonce, resourceID, calldata, handlerResponse)
}

// matchAddressWithHandlerFunc matches a handler address with an associated handler function
func (e *ETHEventHandler) matchAddressWithHandlerFunc(handlerAddress common.Address) (EventHandlerFunc, error) {
	hf, ok := e.eventHandlers[handlerAddress]
	if !ok {
		return nil, errors.New("no corresponding event handler for this address exists")
	}
	return hf, nil
}

// RegisterEventHandler registers an event handler by associating a handler function to a specified address
func (e *ETHEventHandler) RegisterEventHandler(handlerAddress string, handler EventHandlerFunc) {
	if handlerAddress == "" {
		return
	}

	if e.eventHandlers == nil {
		e.eventHandlers = make(map[common.Address]EventHandlerFunc)
	}

	log.Info().Msgf("Registered event handler for address %s", handlerAddress)

	e.eventHandlers[common.HexToAddress(handlerAddress)] = handler
}

// Erc20EventHandler converts data pulled from event logs into message
// handlerResponse can be an empty slice
func Erc20EventHandler(sourceID, destId uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	if len(calldata) < 84 {
		err := errors.New("invalid calldata length: less than 84 bytes")
		return nil, err
	}

	// @dev
	// amount: first 32 bytes of calldata
	amount := calldata[:32]

	// lenRecipientAddress: second 32 bytes of calldata [32:64]
	// does not need to be derived because it is being calculated
	// within ERC20MessageHandler
	// https://github.com/meterio/chainbridge-core/blob/main/chains/evm/voter/message-handler.go#L108

	// recipientAddress: last 20 bytes of calldata
	recipientAddress := calldata[64:]

	return &message.Message{
		Source:       sourceID,
		Destination:  destId,
		DepositNonce: nonce,
		ResourceId:   resourceID,
		Type:         message.FungibleTransfer,
		Payload: []interface{}{
			amount,
			recipientAddress,
		},
		Data: calldata,
	}, nil
}

// GenericEventHandler converts data pulled from generic deposit event logs into message
func GenericEventHandler(sourceID, destId uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	if len(calldata) < 32 {
		err := errors.New("invalid calldata length: less than 32 bytes")
		return nil, err
	}

	// first 32 bytes are metadata length
	metadata := calldata[32:]

	return &message.Message{
		Source:       sourceID,
		Destination:  destId,
		DepositNonce: nonce,
		ResourceId:   resourceID,
		Type:         message.GenericTransfer,
		Payload: []interface{}{
			metadata,
		},
		Data: calldata,
	}, nil
}

// Erc721EventHandler converts data pulled from ERC721 deposit event logs into message
func Erc721EventHandler(sourceID, destId uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	if len(calldata) < 64 {
		err := errors.New("invalid calldata length: less than 84 bytes")
		return nil, err
	}

	// first 32 bytes are tokenId
	tokenId := calldata[:32]

	// 32 - 64 is recipient address length
	recipientAddressLength := big.NewInt(0).SetBytes(calldata[32:64])

	// 64 - (64 + recipient address length) is recipient address
	recipientAddress := calldata[64:(64 + recipientAddressLength.Int64())]

	// (64 + recipient address length) - ((64 + recipient address length) + 32) is metadata length
	medataLength := big.NewInt(0).SetBytes(
		calldata[(64 + recipientAddressLength.Int64()):((64 + recipientAddressLength.Int64()) + 32)],
	)

	// ((64 + recipient address length) + 32) - ((64 + recipient address length) + 32 + metadata length) is metadata
	var metadata []byte
	if medataLength.Cmp(big.NewInt(0)) == 1 {
		metadataStart := (64 + recipientAddressLength.Int64()) + 32
		metadata = calldata[metadataStart : metadataStart+medataLength.Int64()]
	}

	return &message.Message{
		Source:       sourceID,
		Destination:  destId,
		DepositNonce: nonce,
		ResourceId:   resourceID,
		Type:         message.NonFungibleTransfer,
		Payload: []interface{}{
			tokenId,
			recipientAddress,
			metadata,
		},
		Data: calldata,
	}, nil
}
