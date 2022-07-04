// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/ChainSafe/chainbridge-core/lvldb"
	"github.com/ChainSafe/chainbridge-core/util"
	"math/big"
	"time"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmclient"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmgaspricer"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor/signAndSend"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/listener"
	"github.com/ChainSafe/chainbridge-core/chains/evm/voter"
	"github.com/ChainSafe/chainbridge-core/config/chain"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/store"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
)

type EventListener interface {
	ListenToEvents(startBlock, blockConfirmations *big.Int, blockRetryInterval time.Duration, domainID uint8, blockstore *store.BlockStore, stopChn <-chan struct{}, errChn chan<- error) <-chan *message.Message
}

type ProposalVoter interface {
	VoteProposal(message *message.Message) error

	SubmitSignature(message *message.Message) error

	GetSignatures(message *message.Message) ([][]byte, error)
	VoteProposals(message *message.Message, data [][]byte) error
}

// EVMChain is struct that aggregates all data required for
type EVMChain struct {
	listener   EventListener
	writer     ProposalVoter
	blockstore *store.BlockStore
	config     *chain.EVMConfig
}

// SetupDefaultEVMChain sets up an EVMChain with all supported handlers configured
func SetupDefaultEVMChain(db *lvldb.LVLDB, rawConfig map[string]interface{}, txFabric calls.TxFabric, blockstore *store.BlockStore) (*EVMChain, error) {
	config, err := chain.NewEVMConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	client, err := evmclient.NewEVMClient(config)
	if err != nil {
		return nil, err
	}

	gasPricer := evmgaspricer.NewLondonGasPriceClient(client, nil)
	t := signAndSend.NewSignAndSendTransactor(txFabric, gasPricer, client)
	bridgeContract := bridge.NewBridgeContract(client, common.HexToAddress(config.Bridge), t)

	var airDropErc20Contract erc20.ERC20Contract
	if config.AirDropErc20Contract != util.ZeroAddress {
		err = client.EnsureHasBytecode(config.AirDropErc20Contract)
		if err != nil {
			return nil, err
		}

		airDropErc20Contract = *erc20.NewERC20Contract(client, config.AirDropErc20Contract, t)
	}

	var signatureContract signatures.SignaturesContract
	if config.SignatureContract != util.ZeroAddress {
		err = client.EnsureHasBytecode(config.SignatureContract)
		if err != nil {
			return nil, err
		}

		signatureContract = *signatures.NewSignaturesContract(client, config.SignatureContract)
	}

	domainId := config.GeneralChainConfig.Id

	emh := listener.NewEVMMessageHandler(*config, airDropErc20Contract, t)
	eventHandler := listener.NewETHEventHandler(*bridgeContract)
	eventHandler.RegisterEventHandler(config.Erc20Handler, listener.Erc20EventHandler)
	eventHandler.RegisterEventHandler(config.Erc721Handler, listener.Erc721EventHandler)
	eventHandler.RegisterEventHandler(config.GenericHandler, listener.GenericEventHandler)
	evmListener := listener.NewEVMListener(client, eventHandler, common.HexToAddress(config.Bridge), *emh, *domainId, db)

	mh := voter.NewEVMMessageHandler(*bridgeContract, *config, airDropErc20Contract, t)
	mh.RegisterMessageHandler(config.Erc20Handler, voter.ERC20MessageHandler)
	mh.RegisterMessageHandler(config.Erc721Handler, voter.ERC721MessageHandler)
	mh.RegisterMessageHandler(config.GenericHandler, voter.GenericMessageHandler)

	var evmVoter *voter.EVMVoter
	evmVoter, err = voter.NewVoterWithSubscription(db, mh, client, bridgeContract, &signatureContract, *domainId)
	if err != nil {
		log.Error().Msgf("failed creating voter with subscription: %s. Falling back to default voter.", err.Error())
		evmVoter = voter.NewVoter(db, mh, client, bridgeContract, &signatureContract, *domainId)
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

	startBlock, err := c.blockstore.GetStartBlock(
		*c.config.GeneralChainConfig.Id,
		c.config.StartBlock,
		c.config.GeneralChainConfig.LatestBlock,
		c.config.GeneralChainConfig.FreshStart,
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

func (c *EVMChain) Write(msg *message.Message) error {
	return c.writer.VoteProposal(msg)
}

func (c *EVMChain) Read(msg *message.Message) ([][]byte, error) {
	return c.writer.GetSignatures(msg) // GetSignatures
}

func (c *EVMChain) Submit(msg *message.Message) error {
	return c.writer.SubmitSignature(msg) // SubmitSignature
}

func (c *EVMChain) Submits(msg *message.Message, data [][]byte) error {
	return c.writer.VoteProposals(msg, data) // VoteProposals
}

func (c *EVMChain) DomainID() uint8 {
	return *c.config.GeneralChainConfig.Id
}

func (c *EVMChain) MiddleId() uint8 {
	return *c.config.GeneralChainConfig.MiddleId
}
