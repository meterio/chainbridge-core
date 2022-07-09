// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package listener

import (
	"bytes"
	"context"
	"encoding/gob"
	"math/big"
	"strings"
	"time"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmclient"
	"github.com/ChainSafe/chainbridge-core/lvldb"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/store"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethereumTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rs/zerolog/log"
)

type EventHandler interface {
	HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error)
}
type ChainClient interface {
	LatestBlock() (*big.Int, error)
	LatestFinalizedBlock() (*big.Int, error)
	FetchDepositLogs(ctx context.Context, address common.Address, startBlock *big.Int, endBlock *big.Int) ([]*evmclient.DepositLogs, error)
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]ethereumTypes.Log, error)
}

type EVMListener struct {
	chainReader   ChainClient
	eventHandler  EventHandler
	bridgeAddress common.Address

	mh EVMMessageHandler
	id uint8
	db *lvldb.LVLDB
}

// NewEVMListener creates an EVMListener that listens to deposit events on chain
// and calls event handler when one occurs
func NewEVMListener(chainReader ChainClient, handler EventHandler, bridgeAddress common.Address, mh EVMMessageHandler, id uint8, db *lvldb.LVLDB) *EVMListener {
	return &EVMListener{chainReader: chainReader, eventHandler: handler, bridgeAddress: bridgeAddress, mh: mh, id: id, db: db}
}

func (l *EVMListener) ListenToEvents(
	startBlock, blockDelay *big.Int,
	blockRetryInterval time.Duration,
	domainID uint8,
	blockstore *store.BlockStore,
	stopChn <-chan struct{},
	errChn chan<- error,
) <-chan *message.Message {
	ch := make(chan *message.Message)
	go func() {
		for {
			select {
			case <-stopChn:
				return
			default:
				head, err := l.chainReader.LatestBlock()
				if err != nil {
					log.Error().Err(err).Msg("Unable to get latest block")
					time.Sleep(blockRetryInterval)
					continue
				}

				if startBlock == nil {
					startBlock = head
				}

				// Sleep if the difference is less than blockDelay; (latest - current) < BlockDelay
				if big.NewInt(0).Sub(head, startBlock).Cmp(blockDelay) == -1 {
					time.Sleep(blockRetryInterval)
					continue
				}

				query := l.buildQuery(l.bridgeAddress, string(util.ProposalEvent), startBlock, startBlock)
				logch, err := l.chainReader.FilterLogs(context.TODO(), query)
				if err != nil {
					log.Error().Err(err).Msg("failed to FilterLogs")
					continue
				}

				l.trackProposalExecuted(logch)
				proposalPassedMessage := l.trackProposalPassed(logch)
				if proposalPassedMessage != nil {
					proposalPassedMessage.FromDB = true
					ch <- proposalPassedMessage
				}

				logs, err := l.chainReader.FetchDepositLogs(context.Background(), l.bridgeAddress, startBlock, startBlock)
				if err != nil {
					// Filtering logs error really can appear only on wrong configuration or temporary network problem
					// so i do no see any reason to break execution
					log.Error().Err(err).Str("DomainID", string(domainID)).Msgf("Unable to filter logs")
					continue
				}
				for _, eventLog := range logs {
					log.Debug().Msgf("Deposit log found from sender: %s in block: %s with  destinationDomainId: %v, resourceID: %s, depositNonce: %v", eventLog.SenderAddress, startBlock.String(), eventLog.DestinationDomainID, eventLog.ResourceID, eventLog.DepositNonce)
					m, err := l.eventHandler.HandleEvent(domainID, eventLog.DestinationDomainID, eventLog.DepositNonce, eventLog.ResourceID, eventLog.Data, eventLog.HandlerResponse)
					if err != nil {
						log.Error().Str("block", startBlock.String()).Uint8("domainID", domainID).Msgf("%v", err)
					} else {
						log.Debug().Msgf("Resolved message %+v in block %s", m, startBlock.String())
						ch <- m
					}
				}
				if startBlock.Int64()%20 == 0 {
					// Logging process every 20 bocks to exclude spam
					log.Debug().Str("block", startBlock.String()).Uint8("domainID", domainID).Msg("Queried block for deposit events")
				}
				// TODO: We can store blocks to DB inside listener or make listener send something to channel each block to save it.
				//Write to block store. Not a critical operation, no need to retry
				err = blockstore.StoreBlock(startBlock, domainID)
				if err != nil {
					log.Error().Str("block", startBlock.String()).Err(err).Msg("Failed to write latest block to blockstore")
				}
				// Goto next block
				startBlock.Add(startBlock, big.NewInt(1))
			}
		}
	}()
	return ch
}

// buildQuery constructs a query for the bridgeContract by hashing sig to get the event topic
func (v *EVMListener) buildQuery(contract common.Address, sig string, startBlock *big.Int, endBlock *big.Int) ethereum.FilterQuery {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contract},
		Topics: [][]common.Hash{
			{crypto.Keccak256Hash([]byte(sig))},
		},
		FromBlock: startBlock,
		ToBlock:   endBlock,
	}

	return query
}

func (v *EVMListener) trackProposalPassed(vLogs []ethereumTypes.Log) *message.Message {
	for _, vLog := range vLogs {
		abiIst, err := abi.JSON(strings.NewReader(consts.BridgeABI))
		if err != nil {
			continue
		}

		pel, err := unpackProposalEventLog(abiIst, vLog.Data)
		if err != nil {
			log.Error().Msgf("failed unpacking Proposal Executed event log: %v", err)
			continue
		}

		key := []byte{pel.OriginDomainID, v.id, byte(pel.DepositNonce)}
		data, err := v.db.GetByKey(key)
		if err != nil {
			continue
		}

		if pel.Status == message.ProposalStatusCanceled {
			v.db.Delete(key)
			continue
		}

		if pel.Status != message.ProposalStatusPassed {
			continue
		}

		m := message.Message{}

		var network bytes.Buffer
		//Create a decoder and receive a value.
		dec := gob.NewDecoder(&network)
		network.Write(data)
		err = dec.Decode(&m)
		if err != nil {
			log.Error().Msgf("failed Decode Message: %v", err)
			continue
		}

		return &m
	}
	return nil
}

func (v *EVMListener) trackProposalExecuted(vLogs []ethereumTypes.Log) {
	for _, vLog := range vLogs {
		abiIst, err := abi.JSON(strings.NewReader(consts.BridgeABI))
		if err != nil {
			continue
		}

		pel, err := unpackProposalEventLog(abiIst, vLog.Data)
		if err != nil {
			log.Error().Msgf("failed unpacking Proposal Executed event log: %v", err)
			continue
		}

		key := []byte{pel.OriginDomainID, v.id, byte(pel.DepositNonce)}
		data, err := v.db.GetByKey(key)
		if err != nil {
			continue
		}

		if pel.Status == message.ProposalStatusCanceled {
			v.db.Delete(key)
			continue
		}

		if pel.Status != message.ProposalStatusExecuted {
			continue
		}

		m := message.Message{}

		var network bytes.Buffer
		// Create a decoder and receive a value.
		dec := gob.NewDecoder(&network)
		network.Write(data)
		err = dec.Decode(&m)
		if err != nil {
			log.Error().Msgf("failed Decode Message: %v", err)
			continue
		}

		if m.Type != message.FungibleTransfer {
			return
		}

		v.mh.CheckAndExecuteAirDrop(m)
		v.db.Delete(key)
	}
}

func unpackProposalEventLog(abiIst abi.ABI, data []byte) (*evmclient.ProposalEvents, error) {
	var pe evmclient.ProposalEvents

	err := abiIst.UnpackIntoInterface(&pe, "ProposalEvent", data)
	if err != nil {
		return &evmclient.ProposalEvents{}, err
	}

	return &pe, nil
}
