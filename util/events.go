// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package util

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type EventSig string

func (es EventSig) GetTopic() common.Hash {
	return crypto.Keccak256Hash([]byte(es))
}

const (
	Deposit       EventSig = "Deposit(uint8,bytes32,uint64,address,bytes,bytes)"
	ProposalEvent EventSig = "ProposalEvent(uint8,uint64,uint8,bytes32)"
	ProposalVote  EventSig = "ProposalVote(uint8,uint64,uint8,bytes32)"
	SignaturePass EventSig = "SignaturePass(uint8,uint8,uint64,bytes32,bytes,bytes)"
)

type ProposalStatus int

const (
	Inactive ProposalStatus = iota
	Active
	Passed
	Executed
	Cancelled
)

func IsActive(status uint8) bool {
	return ProposalStatus(status) == Active
}

func IsFinalized(status uint8) bool {
	return ProposalStatus(status) == Passed
}

func IsExecuted(status uint8) bool {
	return ProposalStatus(status) == Executed
}
