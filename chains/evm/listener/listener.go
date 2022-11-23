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
	UpdateEndpoint() (string, error)
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
	startBlock, blockConfirmations *big.Int,
	blockWindow *big.Int,
	blockRetryInterval time.Duration,
	domainID uint8,
	blockstore *store.BlockStore,
	stopChn <-chan struct{},
	errChn chan<- error,
) <-chan *message.Message {
	ch := make(chan *message.Message)

	middleChainInited := l.signatureAddress != util.ZeroAddress
	go func() {
		chainName := util.DomainIdToName[l.id]
		log.Info().Msgf("Start to listen events on %v from %v", chainName, startBlock)
		var (
			endBlock   = big.NewInt(0)
			lastReport = time.Now()
			rpcCount   = 0
		)

		for {
			select {
			case <-stopChn:
				return
			default:
				head, err := l.chainReader.LatestBlock()
				rpcCount++
				if err != nil {
					evmclient.ErrCounterLogic(err.Error(), domainID)
					log.Warn().Err(err).Msgf("Unable to get latest block, chain %v", util.DomainIdToName[l.id])

					time.Sleep(blockRetryInterval)
					continue
				}
				chainName := util.DomainIdToName[l.id]

				if startBlock == nil {
					startBlock = head
				}
				endBlock.Add(startBlock, blockWindow)

				if l.openTelemetryInst != nil {
					l.openTelemetryInst.TrackHeadBlock(l.id, head.Int64(), l.fromAddr)
					l.openTelemetryInst.TrackSyncBlock(l.id, startBlock.Int64(), l.fromAddr)
				}

				// Sleep if the difference is less than blockDelay; (latest - current) < BlockDelay
				if new(big.Int).Sub(head, endBlock).Cmp(blockConfirmations) == -1 {
					time.Sleep(blockRetryInterval)
					continue
				}

				eventName := "Deposit"
				if middleChainInited {
					eventName = "SignaturePass"
				}
				log.Debug().Str("chain", chainName).Msgf("Query %v in blocks [%v,%v)", eventName, startBlock.Uint64(), endBlock.Uint64())

				if middleChainInited {
					query := l.buildQuery(l.signatureAddress, string(util.SignaturePass), startBlock, new(big.Int).Sub(endBlock, big.NewInt(1)))
					rpcCount++
					spassLogs, err := l.chainReader.FilterLogs(context.TODO(), query)
					if err != nil {
						evmclient.ErrCounterLogic(err.Error(), domainID)
						log.Warn().Err(err).Msgf("Failed to filter SignaturePass log, chain %v", util.DomainIdToName[l.id])
						continue
					}

					l.trackSignturePass(spassLogs, startBlock, ch)
				} else {
					rpcCount++
					logs, err := l.chainReader.FetchDepositLogs(context.Background(), l.bridgeAddress, startBlock, new(big.Int).Sub(endBlock, big.NewInt(1)))
					if err != nil {
						evmclient.ErrCounterLogic(err.Error(), domainID)
						// Filtering logs error really can appear only on wrong configuration or temporary network problem
						// so i do no see any reason to break execution
						log.Warn().Err(err).Uint8("DomainID", domainID).Str("chain", util.DomainIdToName[domainID]).Msgf("Unable to filter logs")
						continue
					}
					l.trackDeposit(logs, domainID, startBlock, head, ch)
				}

				// TODO: We can store blocks to DB inside listener or make listener send something to channel each block to save it.
				//Write to block store. Not a critical operation, no need to retry
				err = blockstore.StoreBlock(endBlock, domainID)
				if err != nil {
					log.Error().Str("block", startBlock.String()).Err(err).Msgf("Failed to write latest block to blockstore, chain %v", util.DomainIdToName[l.id])
				}
				// Goto next block
				// startBlock.Add(startBlock, big.NewInt(1))
				startBlock.Add(startBlock, blockWindow)

				if time.Since(lastReport) > time.Second*15 {
					log.Info().Str("chain", chainName).Uint64("head", startBlock.Uint64()).Uint64("chainHead", head.Uint64()).Int("rpcCall", rpcCount).Uint64("head", startBlock.Uint64()).Msgf("Still querying %v", eventName)
					lastReport = time.Now()
				}
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
			m.BlockNumber = eventLog.BlockNumber
			m.BlockHash = eventLog.BlockHash

			log.Debug().Msgf("Resolved message %+v in block %s", m, eventLog.BlockNumber)
			ch <- m
		}
	}
}

func (l *EVMListener) trackSignturePass(vLogs []ethereumTypes.Log, startBlock *big.Int, ch chan *message.Message) {
	for _, vLog := range vLogs {
		abiIst, err := abi.JSON(strings.NewReader(consts.SignaturesABI))
		if err != nil {
			log.Error().Msgf("Failed to get ABI for SignaturesPass: %v", err)
			continue
		}

		sigPass, err := unpackSignturePassLog(abiIst, vLog.Data, vLog.Topics)
		if err != nil {
			log.Error().Msgf("Failed to unpack SignturePass: %v", err)
			continue
		}

		log.Debug().Msgf("Resolved event %+v in block %s", sigPass, startBlock.String())

		m := &message.Message{
			Source:       sigPass.OriginDomainID,
			Destination:  sigPass.DestinationDomainID,
			DepositNonce: sigPass.DepositNonce,
			ResourceId:   sigPass.ResourceID,
			Data:         sigPass.Data,
			Type:         message.SignaturePass,
			Payload:      make([]interface{}, 0),
			BlockNumber:  vLog.BlockNumber,
			BlockHash:    vLog.BlockHash,
		}

		ch <- m
	}
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
