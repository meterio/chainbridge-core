// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package listener

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmclient"
	"github.com/ChainSafe/chainbridge-core/opentelemetry"
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
	UpdateEndpoint() error
}

type EVMListener struct {
	chainReader      ChainClient
	eventHandler     EventHandler
	bridgeAddress    common.Address
	signatureAddress common.Address

	id                uint8
	openTelemetryInst *opentelemetry.OpenTelemetry
	fromAddr          string
}

// NewEVMListener creates an EVMListener that listens to deposit events on chain
// and calls event handler when one occurs
func NewEVMListener(chainReader ChainClient, handler EventHandler, bridgeAddress common.Address, signatureAddress common.Address, fromAddr string, id uint8, openTelemetryInst *opentelemetry.OpenTelemetry) *EVMListener {
	return &EVMListener{chainReader: chainReader, eventHandler: handler, bridgeAddress: bridgeAddress, signatureAddress: signatureAddress,
		fromAddr: fromAddr, id: id, openTelemetryInst: openTelemetryInst}
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
	errCounter := 0
	if value, ok := util.DomainIdMappingErrCounter.Load(domainID); ok {
		errCounter = value.(int)
	}

	if l.signatureAddress != util.ZeroAddress {
		go func() {
			startBlock = big.NewInt(0)
			log.Info().Msgf("ListenToEvents, relayChain %v", util.DomainIdToName[l.id])
			for {
				select {
				case <-stopChn:
					return
				default:
					head, err := l.chainReader.LatestBlock()
					if err != nil {
						errCounter = evmclient.IncErrCounterLogic(domainID, true)

						log.Warn().Err(err).Msgf("Unable to get latest block, relayChain %v, err Counter %v", util.DomainIdToName[l.id], errCounter)

						time.Sleep(blockRetryInterval)
						continue
					}
					evmclient.IncErrCounterLogic(domainID, false)

					if startBlock == nil || startBlock.Sign() == 0 {
						startBlock = big.NewInt(0).Sub(head, blockDelay)
					}

					if l.openTelemetryInst != nil {
						l.openTelemetryInst.TrackHeadBlock(l.id, head.Int64(), l.fromAddr)
						l.openTelemetryInst.TrackSyncBlock(l.id, startBlock.Int64(), l.fromAddr)
					}

					log.Debug().Msgf("trackSignturePass head %v, startBlock %v, blockDelay %v, chain %v", head, startBlock, blockDelay, util.DomainIdToName[l.id])

					// Sleep if the difference is less than blockDelay; (latest - current) < BlockDelay
					if big.NewInt(0).Sub(head, startBlock).Cmp(blockDelay) == -1 {
						time.Sleep(blockRetryInterval)
						continue
					}

					query2 := l.buildQuery(l.signatureAddress, string(util.SignaturePass), startBlock, startBlock)
					logch2, err := l.chainReader.FilterLogs(context.TODO(), query2)
					if err != nil {
						evmclient.IncErrCounterLogic(domainID, true)
						log.Warn().Err(err).Msgf("failed to Filter Logs, chain %v", util.DomainIdToName[l.id])
						continue
					}
					evmclient.IncErrCounterLogic(domainID, false)

					proposalPassedMessage := l.trackSignturePass(logch2)
					if proposalPassedMessage != nil {
						ch <- proposalPassedMessage
					}

					if startBlock.Int64()%20 == 0 {
						// Logging process every 20 bocks to exclude spam
						log.Debug().Str("block", startBlock.String()).Uint8("domainID", domainID).Msg("Queried block for deposit events")
					}
					// TODO: We can store blocks to DB inside listener or make listener send something to channel each block to save it.
					//Write to block store. Not a critical operation, no need to retry
					//err = blockstore.StoreBlock(startBlock, domainID)
					//if err != nil {
					//	log.Error().Str("block", startBlock.String()).Err(err).Msg("Failed to write latest block to blockstore")
					//}
					// Goto next block
					startBlock.Add(startBlock, big.NewInt(1))
				}
			}
		}()
		return ch
	}

	go func() {
		log.Info().Msgf("ListenToEvents, startBlock %v, Chain %v", startBlock, util.DomainIdToName[l.id])

		for {
			select {
			case <-stopChn:
				return
			default:
				head, err := l.chainReader.LatestBlock()
				if err != nil {
					errCounter = evmclient.IncErrCounterLogic(domainID, true)
					log.Warn().Err(err).Msgf("Unable to get latest block, chain %v, err Counter %v", util.DomainIdToName[l.id], errCounter)

					time.Sleep(blockRetryInterval)
					continue
				} else {
					evmclient.IncErrCounterLogic(domainID, false)
				}

				if startBlock == nil {
					startBlock = head
				}

				if l.openTelemetryInst != nil {
					l.openTelemetryInst.TrackHeadBlock(l.id, head.Int64(), l.fromAddr)
					l.openTelemetryInst.TrackSyncBlock(l.id, startBlock.Int64(), l.fromAddr)
				}

				log.Debug().Msgf("ListenToEvents head %v, startBlock %v, blockDelay %v, chain %v", head, startBlock, blockDelay, util.DomainIdToName[l.id])

				// Sleep if the difference is less than blockDelay; (latest - current) < BlockDelay
				if big.NewInt(0).Sub(head, startBlock).Cmp(blockDelay) == -1 {
					time.Sleep(blockRetryInterval)
					continue
				}

				logs, err := l.chainReader.FetchDepositLogs(context.Background(), l.bridgeAddress, startBlock, startBlock)
				if err != nil {
					evmclient.IncErrCounterLogic(domainID, true)
					// Filtering logs error really can appear only on wrong configuration or temporary network problem
					// so i do no see any reason to break execution
					log.Warn().Err(err).Uint8("DomainID", domainID).Str("chain", util.DomainIdToName[domainID]).Msgf("Unable to filter logs")
					continue
				}
				evmclient.IncErrCounterLogic(domainID, false)
				l.trackDeposit(logs, domainID, startBlock, head, ch)

				if startBlock.Int64()%20 == 0 {
					// Logging process every 20 bocks to exclude spam
					log.Debug().Str("block", startBlock.String()).Uint8("domainID", domainID).Msg("Queried block for deposit events")
				}
				// TODO: We can store blocks to DB inside listener or make listener send something to channel each block to save it.
				//Write to block store. Not a critical operation, no need to retry
				err = blockstore.StoreBlock(startBlock, domainID)
				if err != nil {
					log.Error().Str("block", startBlock.String()).Err(err).Msgf("Failed to write latest block to blockstore, chain %v", util.DomainIdToName[l.id])
				}
				// Goto next block
				startBlock.Add(startBlock, big.NewInt(1))
			}
		}
	}()

	return ch
}

func (v *EVMListener) HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error) {
	return v.eventHandler.HandleEvent(sourceID, destID, nonce, resourceID, calldata, handlerResponse)
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

func (v *EVMListener) buildMultiQuery(contract common.Address, sigArray []string, startBlock *big.Int, endBlock *big.Int) ethereum.FilterQuery {
	topics := make([][]common.Hash, 0)
	topic := make([]common.Hash, 0)
	for _, sig := range sigArray {
		topic = append(topic, crypto.Keccak256Hash([]byte(sig)))
	}
	topics = append(topics, topic)

	query := ethereum.FilterQuery{
		Addresses: []common.Address{contract},
		Topics:    topics,
		FromBlock: startBlock,
		ToBlock:   endBlock,
	}

	return query
}

func (l *EVMListener) trackDeposit(logs []*evmclient.DepositLogs, domainID uint8, startBlock, head *big.Int, ch chan *message.Message) {
	for _, eventLog := range logs {
		//log.Debug().Msgf("Deposit log found from sender: %s in block: %s with  destinationDomainId: %v, resourceID: %s, depositNonce: %v", eventLog.SenderAddress, startBlock.String(), eventLog.DestinationDomainID, eventLog.ResourceID, eventLog.DepositNonce)
		m, err := l.eventHandler.HandleEvent(domainID, eventLog.DestinationDomainID, eventLog.DepositNonce, eventLog.ResourceID, eventLog.Data, eventLog.HandlerResponse)
		if err != nil {
			log.Error().Str("block", startBlock.String()).Uint8("domainID", domainID).Msgf("%v", err)
		} else {
			m.Start = startBlock
			m.Head = head

			log.Debug().Msgf("Resolved message %+v in block %s", m, startBlock.String())
			ch <- m
		}
	}
	//return ch
}

func (v *EVMListener) trackSignturePass(vLogs []ethereumTypes.Log) *message.Message {
	for _, vLog := range vLogs {
		abiIst, err := abi.JSON(strings.NewReader(consts.SignaturesABI))
		if err != nil {
			log.Error().Msgf("strings.NewReader consts.SignaturesABI err %v", err)
			continue
		}

		pel, err := unpackSignturePassLog(abiIst, vLog.Data, vLog.Topics)
		if err != nil {
			log.Error().Msgf("failed unpackSignturePassLog: %v", err)
			continue
		}

		log.Debug().Msgf("SignaturePass %v", pel)

		m := message.Message{}

		m.Source = pel.OriginDomainID
		m.Destination = pel.DestinationDomainID
		m.DepositNonce = pel.DepositNonce
		m.ResourceId = pel.ResourceID
		m.Data = pel.Data

		//m.Payload, no data, skipped
		//m.Type skip

		m.SPass = true

		return &m
	}
	return nil
}

func unpackSignturePassLog(abiIst abi.ABI, data []byte, topics []common.Hash) (*evmclient.SignaturePass, error) {
	var pe evmclient.SignaturePass

	err := abiIst.UnpackIntoInterface(&pe, "SignaturePass", data)
	if err != nil {
		return &evmclient.SignaturePass{}, err
	}

	if len(topics) < 4 {
		return &evmclient.SignaturePass{}, errors.New("topics out of index")
	}

	originDomainID := topics[1]
	destinationDomainID := topics[2]
	resourceID := topics[3]

	pe.OriginDomainID = originDomainID[len(originDomainID)-1]
	pe.DestinationDomainID = destinationDomainID[len(destinationDomainID)-1]
	pe.ResourceID = resourceID

	return &pe, nil
}
