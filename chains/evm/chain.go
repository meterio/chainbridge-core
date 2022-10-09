// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/ChainSafe/chainbridge-core/opentelemetry"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ChainSafe/chainbridge-core/util"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmclient"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmgaspricer"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor/signAndSend"
	"github.com/ChainSafe/chainbridge-core/chains/evm/listener"
	"github.com/ChainSafe/chainbridge-core/chains/evm/voter"
	"github.com/ChainSafe/chainbridge-core/config/chain"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/store"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
)

type EventListener interface {
	ListenToEvents(startBlock, blockConfirmations *big.Int, blockRetryInterval time.Duration, domainID uint8, blockstore *store.BlockStore, stopChn <-chan struct{}, errChn chan<- error) <-chan *message.Message
	HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error)
}

type ProposalVoter interface {
	VoteProposal(message *message.Message) error

	SubmitSignature(message *message.Message, chainID *big.Int, address *common.Address) error

	GetSignatures(message *message.Message) ([][]byte, error)
	VoteProposals(message *message.Message, data [][]byte, sleepDuration *big.Int) error
	ProposalStatusShouldVoteProposals(m *message.Message) (bool, error)

	ChainID() (*big.Int, error)
	BridgeContractAddress() *common.Address
}

// EVMChain is struct that aggregates all data required for
type EVMChain struct {
	listener   EventListener
	writer     ProposalVoter
	blockstore *store.BlockStore
	config     *chain.EVMConfig
}

// SetupDefaultEVMChain sets up an EVMChain with all supported handlers configured
func SetupDefaultEVMChain(openTelemetryInst *opentelemetry.OpenTelemetry, rawConfig map[string]interface{}, txFabric calls.TxFabric, blockstore *store.BlockStore) (*EVMChain, error) {
	config, err := chain.NewEVMConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	client, err := evmclient.NewEVMClient(config)
	if err != nil {
		return nil, err
	}

	domainId := config.GeneralChainConfig.Id
	fromAddr := config.GeneralChainConfig.From

	gasPricer := evmgaspricer.NewLondonGasPriceClient(client, nil)
	t := signAndSend.NewSignAndSendTransactor(txFabric, gasPricer, client)
	bridgeContract := bridge.NewBridgeContract(client, common.HexToAddress(config.Bridge), t)
	bridgeContract.SetDomainId(*domainId)

	var airDropErc20Contract erc20.ERC20Contract
	if config.AirDropErc20Contract != util.ZeroAddress {
		err = client.EnsureHasBytecode(config.AirDropErc20Contract)
		if err != nil {
			return nil, err
		}

		airDropErc20Contract = *erc20.NewERC20Contract(client, config.AirDropErc20Contract, t)
		airDropErc20Contract.SetDomainId(*domainId)
	}

	var signatureContract signatures.SignaturesContract
	if config.SignatureContract != util.ZeroAddress {
		err = client.EnsureHasBytecode(config.SignatureContract)
		if err != nil {
			return nil, err
		}

		signatureContract = *signatures.NewSignaturesContract(client, config.SignatureContract, t)
		signatureContract.SetDomainId(*domainId)
	}

	eventHandler := listener.NewETHEventHandler(*bridgeContract)
	eventHandler.RegisterEventHandler(config.Erc20Handler, listener.Erc20EventHandler)
	eventHandler.RegisterEventHandler(config.Erc721Handler, listener.Erc721EventHandler)
	eventHandler.RegisterEventHandler(config.GenericHandler, listener.GenericEventHandler)
	evmListener := listener.NewEVMListener(client, eventHandler, common.HexToAddress(config.Bridge), config.SignatureContract, fromAddr, *domainId, openTelemetryInst)

	mh := voter.NewEVMMessageHandler(*bridgeContract)
	mh.RegisterMessageHandler(config.Erc20Handler, voter.ERC20MessageHandler)
	mh.RegisterMessageHandler(config.Erc721Handler, voter.ERC721MessageHandler)
	mh.RegisterMessageHandler(config.GenericHandler, voter.GenericMessageHandler)

	var evmVoter *voter.EVMVoter
	evmVoter, err = voter.NewVoterWithSubscription(*config, mh, client, bridgeContract, &signatureContract, airDropErc20Contract, *domainId, config.RelayId(), config.DelayVoteProposals, t)

	if err != nil {
		log.Warn().Msgf("failed creating voter with subscription: %s. Falling back to default voter.", err.Error())
		evmVoter = voter.NewVoter(*config, mh, client, bridgeContract, &signatureContract, airDropErc20Contract, *domainId, config.DelayVoteProposals, t)
	}

	return NewEVMChain(evmListener, evmVoter, blockstore, config), nil
}

func NewEVMChain(listener EventListener, writer ProposalVoter, blockstore *store.BlockStore, config *chain.EVMConfig) *EVMChain {
	return &EVMChain{listener: listener, writer: writer, blockstore: blockstore, config: config}
}

// PollEvents is the goroutine that polls blocks and searches Deposit events in them.
// Events are then sent to eventsChan.
func (c *EVMChain) PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *message.Message) {
	log.Info().Msg("Polling Blocks...")

	freshStart := false
	freshDomain := c.config.GeneralChainConfig.FreshDomain
	if freshDomain != 0 && uint8(freshDomain) == c.DomainID() {
		freshStart = true
	} else {
		freshStart = c.config.GeneralChainConfig.FreshStart
	}

	startBlock, err := c.blockstore.GetStartBlock(
		*c.config.GeneralChainConfig.Id,
		c.config.StartBlock,
		c.config.GeneralChainConfig.LatestBlock,
		freshStart,
	)
	if err != nil {
		sysErr <- fmt.Errorf("error %w on getting last stored block", err)
		return
	}

	ech := c.listener.ListenToEvents(startBlock, c.config.BlockConfirmations, c.config.BlockRetryInterval, *c.config.GeneralChainConfig.Id, c.blockstore, stop, sysErr)
	for {
		select {
		case <-stop:
			return
		case newEvent := <-ech:
			// Here we can place middlewares for custom logic?
			eventsChan <- newEvent
			continue
		}
	}
}

func (c *EVMChain) HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	return c.listener.HandleEvent(sourceID, destID, nonce, resourceID, calldata, handlerResponse)
}

func (c *EVMChain) Write(msg *message.Message) error {
	return c.writer.VoteProposal(msg)
}

func (c *EVMChain) Read(msg *message.Message) ([][]byte, error) {
	return c.writer.GetSignatures(msg) // GetSignatures
}

func (c *EVMChain) Submit(msg *message.Message, chainID *big.Int, bridgeContractAddress *common.Address) error {
	return c.writer.SubmitSignature(msg, chainID, bridgeContractAddress) // SubmitSignature
}

func (c *EVMChain) Get(msg *message.Message) (bool, error) {
	return c.writer.ProposalStatusShouldVoteProposals(msg)
}

func (c *EVMChain) Submits(msg *message.Message, signatures [][]byte, sleepDuration *big.Int) error {
	return c.writer.VoteProposals(msg, signatures, sleepDuration) // VoteProposals
}

func (c *EVMChain) SignatureSubmit() bool {
	return c.config.SignatureSubmit
}

func (c *EVMChain) DelayVoteProposals() *big.Int {
	return c.config.DelayVoteProposals
}

func (c *EVMChain) DomainID() uint8 {
	return *c.config.GeneralChainConfig.Id
}

func (c *EVMChain) RelayId() uint8 {
	return c.config.RelayId()
}

func (c *EVMChain) ChainID() (*big.Int, error) {
	return c.writer.ChainID()
}

func (c *EVMChain) BridgeContractAddress() *common.Address {
	return c.writer.BridgeContractAddress()
}

func (c *EVMChain) SyncBlockLabels() []attribute.KeyValue {
	id := *c.config.GeneralChainConfig.Id

	return []attribute.KeyValue{{Key: "from", Value: attribute.StringValue(c.config.GeneralChainConfig.From)},
		{Key: "domain_id", Value: attribute.Int64Value(int64(id))},
		{Key: "name", Value: attribute.StringValue(util.DomainIdToName[id])},
		{Key: "type", Value: attribute.StringValue("SyncBlock")},
	}
}

func (c *EVMChain) HeadBlockLabels() []attribute.KeyValue {
	id := *c.config.GeneralChainConfig.Id

	return []attribute.KeyValue{{Key: "from", Value: attribute.StringValue(c.config.GeneralChainConfig.From)},
		{Key: "domain_id", Value: attribute.Int64Value(int64(id))},
		{Key: "name", Value: attribute.StringValue(util.DomainIdToName[id])},
		{Key: "type", Value: attribute.StringValue("HeadBlock")},
	}
}
