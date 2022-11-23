// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
)

type Metrics interface {
	TrackDepositMessage(m *message.Message)
}

type RelayedChain interface {
	PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *message.Message)
	HandleEvent(sourceID, destID uint8, nonce uint64, resourceID types.ResourceID, calldata, handlerResponse []byte) (*message.Message, error)

	DomainID() uint8
	RelayId() uint8

	ChainID() (*big.Int, error)
	BridgeContractAddress() *common.Address
	SyncBlockLabels() []attribute.KeyValue
	HeadBlockLabels() []attribute.KeyValue

	GetSignatures(message *message.Message) ([][]byte, error)
	Get(message *message.Message) (bool, error)
	VoteOnDest(message *message.Message) error
	VoteOnRelay(message *message.Message, chainID *big.Int, address *common.Address) error
	ExecOnDest(message *message.Message, data [][]byte, sleepDuration *big.Int) error
	SignatureSubmit() bool
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
			go r.route(m, messagesChannel)
			continue
		case <-stop:
			return
		}
	}
}

// Route function winds destination writer by mapping DestinationID from message to registered writer.
func (r *Relayer) route(m *message.Message, msgCh chan *message.Message) {
	//r.metrics.TrackDepositMessage(m)

	sourceChain, ok := r.registry[m.Source]
	if !ok {
		log.Error().Msgf("no resolver for sourceID %v to send message registered", m.Destination)
		return
	}
	middleId := sourceChain.RelayId() // if zero?, use old logic.

	var middleChain RelayedChain
	if middleId != 0 {
		middleChain, ok = r.registry[middleId]
		if !ok {
			log.Error().Msgf("no resolver for middleID %v to send message registered", m.Destination)
			return
		}
	}

	destChain, ok := r.registry[m.Destination]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return
	}
	destChainID, err := destChain.ChainID()
	if err != nil {
		log.Error().Err(fmt.Errorf("error getting chainId: %w on dest chain %v", err, m.Destination))
	}

	if middleChain != nil && middleChain.SignatureSubmit() {
		// relay chain enabled

		// scenario #1: SignaturePass event received on relay chain
		// submit merged signature to destination chain directly
		if m.Type == message.SignaturePass || m.Type == message.ArtificialPass {
			mm, err := destChain.HandleEvent(m.Source, m.Destination, m.DepositNonce, m.ResourceId, m.Data, []byte{})
			if err != nil {
				log.Error().Msgf("could not handle SigPass: %v", err)
				panic("help")
			}
			mm.Type = m.Type
			log.Info().Str("relay", "enabled").Msgf("Recv: %v, submit signatures to dest chain %v", m, m.Destination)
			sigs, err := middleChain.GetSignatures(m) // getSignatures
			if err != nil {
				log.Error().Str("msg", m.ID()).Err(fmt.Errorf("error getting signatures: %w", err))
			}
			log.Info().Msgf("signature length: %v", len(sigs))
			for _, sig := range sigs {
				log.Info().Msgf("Signature: %v", hex.EncodeToString(sig))
			}

			err = destChain.ExecOnDest(mm, sigs, big.NewInt(1)) // voteProposals
			if err != nil {
				log.Error().Str("msg", mm.ID()).Err(fmt.Errorf("error exec on dest chain: %w", err))
			}

			return
		}

		// scenario #2: Deposit event received on source chain, and relay chain is enabled
		// submit signature to relay chain
		log.Info().Str("relay", "enabled").Msgf("Recv: %v, vote on relay chain %v", m, middleId)
		err = middleChain.VoteOnRelay(m, destChainID, destChain.BridgeContractAddress()) // submitSignature
		if err != nil {
			if err == util.ErrAlreadyPassed {
				m.Type = message.ArtificialPass
				msgCh <- m
			}
			log.Error().Str("msg", m.ID()).Err(fmt.Errorf("error vote on relay chain: %w", err))
		}
		return
	}

	// special case for polis network
	blackList := []string{
		"0x8cafd0397e1b09199A1B1239030Cc6b011AE696d",
	}
	blackMap := make(map[string]bool) // key: address in lower case without 0x-prefix, value: true
	for _, b := range blackList {
		blackMap[strings.ToLower(strings.ReplaceAll(b, "0x", ""))] = true
	}

	// whiteList := []string{}
	// whiteMap := make(map[string]bool)
	// for _, w := range whiteList {
	// 	whiteMap[strings.ToLower(strings.ReplaceAll(w, "0x", ""))] = true
	// }
	if len(m.Payload) >= 2 && m.Source == 7 {
		raddr := m.Payload[1].([]byte)
		recipientAddr := strings.ToLower(hex.EncodeToString(raddr))

		// return if it's black listed
		if _, blacked := blackMap[recipientAddr]; blacked {
			log.Warn().Msgf("recipient address %v is black listed, won't process this Deposit %v", recipientAddr, m)
			return
		}

		// return if it's not white listed
		// if _, whited := whiteMap[recipientAddr]; !whited {
		// log.Warn().Msgf("recipient address %v is not white listed, won't process this Deposit %v", recipientAddr, m)
		// return
		// }
	}

	// scenario #3: Deposit event received and middle chain is not enabled
	// submit signature to dest chain directly
	log.Debug().Str("relay", "disabled").Msgf("Recv: %v, submit signature to dest chain", m)
	for _, mp := range r.messageProcessors {
		if err := mp(m); err != nil {
			log.Error().Str("msg", m.ID()).Err(fmt.Errorf("error processing: %w ", err))
			return
		}
	}

	if err := destChain.VoteOnDest(m); err != nil { // voteProposal
		log.Error().Str("msg", m.ID()).Err(err).Msgf("error vote on dest chain: %w", err)
		return
	}
}

func (r *Relayer) addRelayedChain(c RelayedChain) {
	if r.registry == nil {
		r.registry = make(map[uint8]RelayedChain)
	}
	domainID := c.DomainID()
	r.registry[domainID] = c
}
