// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/gob"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/signer/core"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/chains/evm/voter/proposal"
	"github.com/ChainSafe/chainbridge-core/lvldb"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethereumTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	beecrypto "github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/crypto/eip712"
	"github.com/rs/zerolog/log"
)

const (
	maxSimulateVoteChecks = 5
	maxShouldVoteChecks   = 40
	shouldVoteCheckPeriod = 15
)

var (
	Sleep = time.Sleep
)

type ChainClient interface {
	RelayerAddress() common.Address
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
	SubscribePendingTransactions(ctx context.Context, ch chan<- common.Hash) (*rpc.ClientSubscription, error)
	TransactionByHash(ctx context.Context, hash common.Hash) (tx *ethereumTypes.Transaction, isPending bool, err error)
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- ethereumTypes.Log) (ethereum.Subscription, error)
	LatestBlock() (*big.Int, error)
	ChainID(ctx context.Context) (*big.Int, error)
	PrivateKey() *ecdsa.PrivateKey

	calls.ContractCallerDispatcher
}

type MessageHandler interface {
	HandleMessage(m *message.Message) (*proposal.Proposal, error)
}

type BridgeContract interface {
	IsProposalVotedBy(by common.Address, p *proposal.Proposal) (bool, error)
	VoteProposal(proposal *proposal.Proposal, opts transactor.TransactOptions) (*common.Hash, error)
	VoteProposals(domainID uint8, depositNonce uint64, resourceID [32]byte, data []byte, signatures [][]byte, opts transactor.TransactOptions) (*common.Hash, error)
	SimulateVoteProposal(proposal *proposal.Proposal) error
	ProposalStatus(p *proposal.Proposal) (message.ProposalStatus, error)
	GetThreshold() (uint8, error)
	ContractAddress() *common.Address
}

type SignatureContract interface {
	SubmitSignature(originDomainID uint8, destinationDomainID uint8, destinationBridge common.Address, depositNonce uint64, resourceID [32]byte, data []byte, signature []byte, opts transactor.TransactOptions) (*common.Hash, error)
	GetSignatures(domainID uint8, depositNonce uint64, resourceID [32]byte, data []byte) ([][]byte, error)
}

type EVMVoter struct {
	mh                   MessageHandler
	client               ChainClient
	bridgeContract       BridgeContract
	signatureContract    SignatureContract
	pendingProposalVotes map[common.Hash]uint8
	id                   uint8
	db                   *lvldb.LVLDB
}

// NewVoterWithSubscription creates an instance of EVMVoter that votes for
// proposals on chain.
//
// It is created with a pending proposal subscription that listens to
// pending voteProposal transactions and avoids wasting gas on sending votes
// for transactions that will fail.
// Currently, officially supported only by Geth nodes.
func NewVoterWithSubscription(db *lvldb.LVLDB, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, id uint8) (*EVMVoter, error) {
	voter := &EVMVoter{
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		db:                   db,
	}

	ch := make(chan common.Hash)

	_, err := client.SubscribePendingTransactions(context.TODO(), ch)
	if err != nil {
		return nil, err
	}
	go voter.trackProposalPendingVotes(ch)

	return voter, nil
}

// NewVoter creates an instance of EVMVoter that votes for proposal on chain.
//
// It is created without pending proposal subscription and is a fallback
// for nodes that don't support pending transaction subscription and will vote
// on proposals that already satisfy threshold.
func NewVoter(db *lvldb.LVLDB, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, id uint8) *EVMVoter {
	return &EVMVoter{
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		db:                   db,
	}
}

// VoteProposal checks if relayer already voted and is threshold
// satisfied and casts a vote if it isn't.
func (v *EVMVoter) VoteProposal(m *message.Message) error {
	prop, err := v.mh.HandleMessage(m)
	if err != nil {
		return err
	}

	votedByTheRelayer, err := v.bridgeContract.IsProposalVotedBy(v.client.RelayerAddress(), prop)
	if err != nil {
		return err
	}
	if votedByTheRelayer {
		return nil
	}

	shouldVote, err := v.shouldVoteForProposal(prop, 0)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	if !shouldVote {
		log.Debug().Msgf("Proposal %+v already satisfies threshold", prop)
		return nil
	}
	err = v.repetitiveSimulateVote(prop, 0)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	hash, err := v.bridgeContract.VoteProposal(prop, transactor.TransactOptions{})
	if err != nil {
		return fmt.Errorf("voting failed. Err: %w", err)
	}

	// only ERC20 allow to airdrop
	if m.Type == message.FungibleTransfer {
		err = v.saveMessage(*m)
		if err != nil {
			return err
		}
	}

	log.Debug().Str("hash", hash.String()).Uint64("nonce", prop.DepositNonce).Msgf("Voted")
	return nil
}

func (v *EVMVoter) SubmitSignature(m *message.Message) error {
	return v.BeeSubmitSignature(m)
}

//func (v *EVMVoter) submitSignature(m *message.Message) error {
//	log.Info().Msgf("SubmitSignature message: %v", m)
//
//	name := "PermitBridge"
//	version := "1.0"
//	chainId, err := v.client.ChainID(context.TODO())
//	if err != nil {
//		return err
//	}
//	verifyingContract := v.bridgeContract.ContractAddress()
//
//	typedData := core.TypedData{
//		Types: core.Types{
//			"EIP712Domain": []core.Type{
//				{"name", "string"},
//				{"version", "string"},
//				{"chainId", "uint256"},
//				{"verifyingContract", "address"},
//			},
//			"PermitBridge": []core.Type{
//				{"domainID", "uint256"},
//				{"depositNonce", "uint256"},
//				{"resourceID", "bytes32"},
//				{"data", "bytes"}}},
//		PrimaryType: "PermitBridge",
//		Domain:      core.TypedDataDomain{Name: name, Version: version, ChainId: math.NewHexOrDecimal256(chainId.Int64()), VerifyingContract: verifyingContract.String()},
//		Message: core.TypedDataMessage{
//			"domainID":     math.NewHexOrDecimal256(int64(m.Source)),
//			"depositNonce": math.NewHexOrDecimal256(int64(m.DepositNonce)),
//			"resourceID":   m.ResourceId[:],
//			"data":         m.Data,
//		}}
//
//	log.Info().Msgf("EncodeForSigning, typedData %v", typedData)
//	rawData, err := EncodeForSigning(&typedData)
//	if err != nil {
//		return err
//	}
//
//	log.Info().Msg("Keccak256Hash")
//	hashData := crypto.Keccak256Hash(rawData)
//	log.Info().Msg("Sign")
//	signatureBytes, err := v.client.Sign(hashData.Bytes())
//	if err != nil {
//		return err
//	}
//
//	hash, err := v.signatureContract.SubmitSignature(m.Source, m.Destination, *verifyingContract, m.DepositNonce, m.ResourceId, m.Data, signatureBytes, transactor.TransactOptions{})
//	if err != nil {
//		return err
//	}
//	log.Debug().Str("hash", hash.String()).Msgf("SubmitSignature")
//
//	err = v.saveMessage(*m)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

func (v *EVMVoter) BeeSubmitSignature(m *message.Message) error {
	log.Info().Msgf("BeeSubmitSignature message: %v", m)

	privKey := v.client.PrivateKey()
	log.Info().Msgf("privKey %x", privKey)
	log.Info().Msgf("PublicKey %x", privKey.PublicKey)
	signer := beecrypto.NewDefaultSigner(privKey)

	name := "PermitBridge"
	version := "1.0"
	chainId, err := v.client.ChainID(context.TODO())
	if err != nil {
		return err
	}
	verifyingContract := v.bridgeContract.ContractAddress()

	typedData := &eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{"name", "string"},
				{"version", "string"},
				{"chainId", "uint256"},
				{"verifyingContract", "address"},
			},
			"PermitBridge": {
				{"domainID", "uint256"},
				{"depositNonce", "uint256"},
				{"resourceID", "bytes32"},
				{"data", "bytes"}}},
		PrimaryType: "PermitBridge",
		Domain:      eip712.TypedDataDomain{Name: name, Version: version, ChainId: math.NewHexOrDecimal256(chainId.Int64()), VerifyingContract: verifyingContract.String()},
		Message: eip712.TypedDataMessage{
			"domainID":     math.NewHexOrDecimal256(int64(m.Source)),
			"depositNonce": math.NewHexOrDecimal256(int64(m.DepositNonce)),
			"resourceID":   m.ResourceId[:],
			"data":         m.Data,
		}}

	//var testTypedData = &eip712.TypedData{
	//	Domain: eip712.TypedDataDomain{
	//		Name:    "test",
	//		Version: "1.0",
	//	},
	//	Types: eip712.Types{
	//		"EIP712Domain": {
	//			{
	//				Name: "name",
	//				Type: "string",
	//			},
	//			{
	//				Name: "version",
	//				Type: "string",
	//			},
	//		},
	//		"MyType": {
	//			{
	//				Name: "test",
	//				Type: "string",
	//			},
	//		},
	//	},
	//	Message: eip712.TypedDataMessage{
	//		"test": "abc",
	//	},
	//	PrimaryType: "MyType",
	//}

	rawData, err := eip712.EncodeForSigning(typedData)
	if err != nil {
		return err
	}
	log.Info().Msgf("EncodeForSigning get rawData %x", rawData)

	sighash, err := beecrypto.LegacyKeccak256(rawData)
	if err != nil {
		return err
	}
	log.Info().Msgf("LegacyKeccak256 get sighash %x", sighash)

	log.Info().Msgf("typedData %v", typedData)
	sig, err := signer.SignTypedData(typedData)
	if err != nil {
		return err
	}

	p1, err := beecrypto.Recover(sig, sighash)
	if err != nil {
		return err
	}
	log.Info().Msgf("p1 PublicKey %x", p1)
	p2, err := beecrypto.RecoverEIP712(sig, typedData)
	if err != nil {
		return err
	}
	log.Info().Msgf("p2 PublicKey %x", p2)

	hash, err := v.signatureContract.SubmitSignature(m.Source, m.Destination, *verifyingContract, m.DepositNonce, m.ResourceId, m.Data, sig, transactor.TransactOptions{})
	if err != nil {
		return err
	}
	log.Debug().Str("hash", hash.String()).Msgf("SubmitSignature")

	err = v.saveMessage(*m)
	if err != nil {
		return err
	}

	return nil

	//return err
	//
	//log.Info().Msgf("EncodeForSigning, typedData %v", typedData)
	//rawData, err := EncodeForSigning(&typedData)
	//if err != nil {
	//	return err
	//}
	//
	//log.Info().Msg("Keccak256Hash")
	//hashData := crypto.Keccak256Hash(rawData)
	//log.Info().Msg("Sign")
	//signatureBytes, err := v.client.Sign(hashData.Bytes())
	//if err != nil {
	//	return err
	//}
	//
	//hash, err := v.signatureContract.SubmitSignature(m.Source, m.Destination, *verifyingContract, m.DepositNonce, m.ResourceId, m.Data, signatureBytes, transactor.TransactOptions{})
	//if err != nil {
	//	return err
	//}
	//log.Debug().Str("hash", hash.String()).Msgf("SubmitSignature")
	//
	//err = v.saveMessage(*m)
	//if err != nil {
	//	return err
	//}
	//
	//return nil
}

//func EncodeForSigning(typedData *core.TypedData) ([]byte, error) {
//	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
//	if err != nil {
//		//panic(err)
//		return nil, err
//	}
//
//	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
//	if err != nil {
//		//panic(err)
//		return nil, err
//	}
//
//	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
//	return rawData, nil
//}

func (v *EVMVoter) GetSignatures(m *message.Message) ([][]byte, error) {
	data, err := v.signatureContract.GetSignatures(m.Source, m.DepositNonce, m.ResourceId, m.Data)
	if err != nil {
		return [][]byte{}, err
	}
	return data, nil
}

func (v *EVMVoter) VoteProposals(m *message.Message, data [][]byte) error {
	log.Info().Msgf("VoteProposals message: %v", m)

	hash, err := v.bridgeContract.VoteProposals(m.Source, m.DepositNonce, m.ResourceId, m.Data, data, transactor.TransactOptions{})
	if err != nil {
		return err
	}
	log.Debug().Str("hash", hash.String()).Msgf("VoteProposals")

	return nil
}

func (v *EVMVoter) saveMessage(m message.Message) error {
	var network bytes.Buffer // Stand-in for the network.

	// Create an encoder and send a value.
	enc := gob.NewEncoder(&network)
	err := enc.Encode(m)
	if err != nil {
		log.Fatal().Err(err)
		return err
	}

	key := []byte{m.Source, m.Destination, byte(m.DepositNonce)}

	err = v.db.SetByKey(key, network.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// shouldVoteForProposal checks if proposal already has threshold with pending
// proposal votes from other relayers.
// Only works properly in conjuction with NewVoterWithSubscription as without a subscription
// no pending txs would be received and pending vote count would be 0.
func (v *EVMVoter) shouldVoteForProposal(prop *proposal.Proposal, tries int) (bool, error) {
	propID := prop.GetID()
	defer delete(v.pendingProposalVotes, propID)

	// random delay to prevent all relayers checking for pending votes
	// at the same time and all of them sending another tx
	Sleep(time.Duration(rand.Intn(shouldVoteCheckPeriod)) * time.Second)

	ps, err := v.bridgeContract.ProposalStatus(prop)
	if err != nil {
		return false, err
	}

	if ps.Status == message.ProposalStatusExecuted || ps.Status == message.ProposalStatusCanceled {
		return false, nil
	}

	threshold, err := v.bridgeContract.GetThreshold()
	if err != nil {
		return false, err
	}

	if ps.YesVotesTotal+v.pendingProposalVotes[propID] >= threshold && tries < maxShouldVoteChecks {
		// Wait until proposal status is finalized to prevent missing votes
		// in case of dropped txs
		tries++
		return v.shouldVoteForProposal(prop, tries)
	}

	return true, nil
}

// repetitiveSimulateVote repeatedly tries(5 times) to simulate vore proposal call until it succeeds
func (v *EVMVoter) repetitiveSimulateVote(prop *proposal.Proposal, tries int) error {
	err := v.bridgeContract.SimulateVoteProposal(prop)
	if err != nil {
		if tries < maxSimulateVoteChecks {
			tries++
			return v.repetitiveSimulateVote(prop, tries)
		}
		return err
	} else {
		return nil
	}
}

// trackProposalPendingVotes tracks pending voteProposal txs from
// other relayers and increases count of pending votes in pendingProposalVotes map
// by proposal unique id.
func (v *EVMVoter) trackProposalPendingVotes(ch chan common.Hash) {
	for msg := range ch {
		txData, _, err := v.client.TransactionByHash(context.TODO(), msg)
		if err != nil {
			log.Error().Err(err)
			continue
		}

		a, err := abi.JSON(strings.NewReader(consts.BridgeABI))
		if err != nil {
			log.Error().Err(err)
			continue
		}

		if len(txData.Data()) < 4 {
			continue
		}

		m, err := a.MethodById(txData.Data()[:4])
		if err != nil {
			continue
		}

		data, err := m.Inputs.UnpackValues(txData.Data()[4:])
		if err != nil {
			log.Error().Err(err)
			continue
		}

		if m.Name == "voteProposal" {
			source := data[0].(uint8)
			depositNonce := data[1].(uint64)
			prop := proposal.Proposal{
				Source:       source,
				DepositNonce: depositNonce,
			}

			go v.increaseProposalVoteCount(msg, prop.GetID())
		}
	}
}

// increaseProposalVoteCount increases pending proposal vote for target proposal
// and decreases it when transaction is mined.
func (v *EVMVoter) increaseProposalVoteCount(hash common.Hash, propID common.Hash) {
	v.pendingProposalVotes[propID]++

	_, err := v.client.WaitAndReturnTxReceipt(hash)
	if err != nil {
		log.Error().Err(err)
	}

	v.pendingProposalVotes[propID]--
}
