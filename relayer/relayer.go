// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/rs/zerolog/log"
)

type Metrics interface {
	TrackDepositMessage(m *message.Message)
}

type RelayedChain interface {
	PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *message.Message)

	DomainID() uint8
	MiddleId() uint8

	Read(message *message.Message) ([][]byte, error)
	Write(message *message.Message) error
	Submit(message *message.Message) error
	Submits(message *message.Message, data [][]byte) error
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
	middleId := sourceChain.MiddleId() // if zero?, use old logic.

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
	if m.FromDB {
		log.Info().Msgf("route case 1, message %v", m)
		data, err := middleChain.Read(m)
		if err != nil {
			log.Error().Msgf(err.Error())
		}
		err = destChain.Submits(m, data)
		if err != nil {
			log.Error().Err(fmt.Errorf("error Submits %w processing mesage %v", err, m))
		}

		return
	}

	// case 2
	if middleChain != nil {
		log.Info().Msgf("route case 2, message %v", m)
		err := middleChain.Submit(m)
		if err != nil {
			log.Error().Err(fmt.Errorf("error Submit %w processing mesage %v", err, m))
		}
		return
	}

	// case 3
	log.Info().Msgf("route case 3, message %v", m)
	for _, mp := range r.messageProcessors {
		if err := mp(m); err != nil {
			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
			return
		}
	}

	log.Debug().Msgf("Sending message %+v to destination %v", m, m.Destination)

	if err := destChain.Write(m); err != nil {
		log.Error().Err(err).Msgf("writing message %+v", m)
		return
	}
	return
}

func (r *Relayer) toMiddleChain(m *message.Message) bool {
	sourceChain, ok := r.registry[m.Source]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return false
	}
	middleId := sourceChain.MiddleId() // if zero?, use old logic.

	middleChain, ok := r.registry[middleId]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return false
	}

	for _, mp := range r.messageProcessors {
		if err := mp(m); err != nil {
			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
			return false
		}
	}

	log.Debug().Msgf("Sending message %+v to middle %v", m, sourceChain.MiddleId())

	if err := middleChain.Submit(m); err != nil {
		log.Error().Err(err).Msgf("writing message %+v", m)
		return false
	}

	return true
}

func (r *Relayer) toDestChain(m *message.Message) {
	destChain, ok := r.registry[m.Destination]
	if !ok {
		log.Error().Msgf("no resolver for destID %v to send message registered", m.Destination)
		return
	}

	for _, mp := range r.messageProcessors {
		if err := mp(m); err != nil {
			log.Error().Err(fmt.Errorf("error %w processing mesage %v", err, m))
			return
		}
	}

	log.Debug().Msgf("Sending message %+v to destination %v", m, m.Destination)

	if err := destChain.Write(m); err != nil {
		log.Error().Err(err).Msgf("writing message %+v", m)
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
