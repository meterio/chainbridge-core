// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"math/big"
	"time"
)

type Metrics interface {
	TrackDepositMessage(m *message.Message)
}

type RelayedChain interface {
	PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *message.Message)

	DomainID() uint8
	RelayId() uint8

	ChainID() (*big.Int, error)
	BridgeContractAddress() *common.Address

	Read(message *message.Message) ([][]byte, error)
	Get(message *message.Message) (bool, error)
	Write(message *message.Message) error
	Submit(message *message.Message, chainID *big.Int, address *common.Address) error
	Submits(message *message.Message, data [][]byte, sleepDuration *big.Int) error
	SignatureSubmit() bool
	DelayVoteProposals() *big.Int
}

func NewRelayer(chains []RelayedChain, metrics Metrics, messageProcessors ...message.MessageProcessor) *Relayer {
	return &Relayer{relayedChains: chains, messageProcessors: messageProcessors, metrics: metrics}
}

type Relayer struct {
	metrics           Metrics
	relayedChains     []RelayedChain
	registry          map[uint8]RelayedChain
	messageProcessors []message.MessageProcessor
}

// Start function starts the relayer. Relayer routine is starting all the chains
// and passing them with a channel that accepts unified cross chain message format
func (r *Relayer) Start(stop <-chan struct{}, sysErr chan error) {
	log.Debug().Msgf("Starting relayer")

	messagesChannel := make(chan *message.Message)
	for _, c := range r.relayedChains {
		log.Debug().Msgf("Starting chain %v", c.DomainID())
		r.addRelayedChain(c)
		go c.PollEvents(stop, sysErr, messagesChannel)
	}

	for {
		select {
		case m := <-messagesChannel:
			go r.route(m)
			continue
		case <-stop:
			return
		}
	}
}

// Route function winds destination writer by mapping DestinationID from message to registered writer.
func (r *Relayer) route(m *message.Message) {
	r.metrics.TrackDepositMessage(m)

	sourceChain, ok := r.registry[m.Source]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return
	}
	middleId := sourceChain.RelayId() // if zero?, use old logic.

	var middleChain RelayedChain
	if middleId != 0 {
		middleChain, ok = r.registry[middleId]
		if !ok {
			log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
			return
		}
	}

	destChain, ok := r.registry[m.Destination]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return
	}

	// case 1
	if m.FromDB && middleChain.SignatureSubmit() {
		log.Debug().Msgf("route case 1, signaturePass, message %v", m)
		data, err := middleChain.Read(m) // getSignatures
		if err != nil {
			log.Error().Msgf(err.Error())
		}
		err = destChain.Submits(m, data, middleChain.DelayVoteProposals()) // voteProposals
		if err != nil {
			log.Error().Err(fmt.Errorf("error Submits %w processing mesage %v", err, m))
		}

		return
	}

	// case 2
	if middleChain != nil {
		log.Debug().Msgf("route case 2, deposit with relayChain, message %v", m)
		destChainID, err := destChain.ChainID()
		if err != nil {
			log.Error().Err(fmt.Errorf("error Submit %w get destChainID %v", err, m))
		}
		err = middleChain.Submit(m, destChainID, destChain.BridgeContractAddress()) // submitSignature
		if err != nil {
			if err.Error() == util.OVERTHRESHOLD && middleChain.SignatureSubmit() {
				// case 4
				delayConfirmations := middleChain.DelayVoteProposals()
				log.Debug().Msgf("middleChain before sleep %v", delayConfirmations)
				<-time.After(time.Second * time.Duration(delayConfirmations.Int64()))
				log.Debug().Msgf("middleChain after sleep %v", delayConfirmations)

				statusShouldVoteProposals, err := destChain.Get(m) // ProposalStatusShouldVoteProposals
				if err != nil {
					log.Error().Msgf(err.Error())
					return
				}

				if statusShouldVoteProposals {
					log.Debug().Msgf("route case 2 to 1, message %v", m)
					data, err := middleChain.Read(m) // getSignatures
					if err != nil {
						log.Error().Msgf(err.Error())
					}
					err = destChain.Submits(m, data, big.NewInt(0)) // voteProposals
					if err != nil {
						log.Error().Err(fmt.Errorf("error Submits %w processing mesage %v", err, m))
					}

					return
				}
			}
			log.Error().Err(fmt.Errorf("error Submit %w processing mesage %v", err, m))
		}
		return
	}

	// case 3
	log.Debug().Msgf("route case 3, deposit without relayChain, message %v", m)
	for _, mp := range r.messageProcessors {
		if err := mp(m); err != nil {
			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
			return
		}
	}

	log.Debug().Msgf("Sending message %+v to destination %v", m, m.Destination)

	if err := destChain.Write(m); err != nil { // voteProposal
		log.Error().Err(err).Msgf("writing message %+v", m)
		return
	}
	return
}

//func (r *Relayer) toMiddleChain(m *message.Message) bool {
//	sourceChain, ok := r.registry[m.Source]
//	if !ok {
//		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
//		return false
//	}
//	middleId := sourceChain.RelayId() // if zero?, use old logic.
//
//	middleChain, ok := r.registry[middleId]
//	if !ok {
//		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
//		return false
//	}
//
//	for _, mp := range r.messageProcessors {
//		if err := mp(m); err != nil {
//			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
//			return false
//		}
//	}
//
//	log.Debug().Msgf("Sending message %+v to middle %v", m, sourceChain.RelayId())
//
//	if err := middleChain.Submit(m); err != nil {
//		log.Error().Err(err).Msgf("writing message %+v", m)
//		return false
//	}
//
//	return true
//}

//func (r *Relayer) toDestChain(m *message.Message) {
//	destChain, ok := r.registry[m.Destination]
//	if !ok {
//		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
//		return
//	}
//
//	for _, mp := range r.messageProcessors {
//		if err := mp(m); err != nil {
//			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
//			return
//		}
//	}
//
//	log.Debug().Msgf("Sending message %+v to destination %v", m, m.Destination)
//
//	if err := destChain.Write(m); err != nil {
//		log.Error().Err(err).Msgf("writing message %+v", m)
//		return
//	}
//}

func (r *Relayer) addRelayedChain(c RelayedChain) {
	if r.registry == nil {
		r.registry = make(map[uint8]RelayedChain)
	}
	domainID := c.DomainID()
	r.registry[domainID] = c
}
