// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/ChainSafe/chainbridge-core/config/chain"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ChainSafe/chainbridge-core/util"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"strconv"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

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
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethereumTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
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
	GetProposal(source uint8, depositNonce uint64, resourceId types.ResourceID, data []byte) (message.ProposalStatus, error)
	GetThreshold() (uint8, error)
	ContractAddress() *common.Address
}

type SignatureContract interface {
	ContractAddress() *common.Address
	SubmitSignature(originDomainID uint8, destinationDomainID uint8, depositNonce uint64, resourceID [32]byte, data []byte, signature []byte, opts transactor.TransactOptions) (*common.Hash, error)

	GetThreshold(domain uint8) (uint8, error)
	GetSignatures(domainID uint8, destinationDomainID uint8, depositNonce uint64, resourceID [32]byte, data []byte) ([][]byte, error)
}

type EVMVoter struct {
	mh                   MessageHandler
	client               ChainClient
	bridgeContract       BridgeContract
	signatureContract    SignatureContract
	pendingProposalVotes map[common.Hash]uint8
	id                   uint8
	delayVoteProposals   *big.Int
	airDropErc20Contract erc20.ERC20Contract
	cfg                  chain.EVMConfig
	t                    transactor.Transactor
}

// NewVoterWithSubscription creates an instance of EVMVoter that votes for
// proposals on chain.
//
// It is created with a pending proposal subscription that listens to
// pending voteProposal transactions and avoids wasting gas on sending votes
// for transactions that will fail.
// Currently, officially supported only by Geth nodes.
func NewVoterWithSubscription(config chain.EVMConfig, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, airDropErc20Contract erc20.ERC20Contract, id uint8, relayId uint8, delayVoteProposals *big.Int, t transactor.Transactor) (*EVMVoter, error) {
	voter := &EVMVoter{
		cfg:                  config,
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		airDropErc20Contract: airDropErc20Contract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		//db:                   db,
		delayVoteProposals: delayVoteProposals,
		t:                  t,
	}

	if relayId == 0 {
		ch := make(chan common.Hash)

		_, err := client.SubscribePendingTransactions(context.TODO(), ch)
		if err != nil {
			return nil, err
		}
		go voter.trackProposalPendingVotes(ch)
	}

	return voter, nil
}

// NewVoter creates an instance of EVMVoter that votes for proposal on chain.
//
// It is created without pending proposal subscription and is a fallback
// for nodes that don't support pending transaction subscription and will vote
// on proposals that already satisfy threshold.
func NewVoter(config chain.EVMConfig, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, airDropErc20Contract erc20.ERC20Contract, id uint8, delayVoteProposals *big.Int, t transactor.Transactor) *EVMVoter {
	return &EVMVoter{
		cfg:                  config,
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		airDropErc20Contract: airDropErc20Contract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		//db:                   db,
		delayVoteProposals: delayVoteProposals,
		t:                  t,
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
		log.Info().Msgf("Proposal %+v already satisfies threshold", prop)
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

	v.CheckAndExecuteAirDrop(*m)

	log.Info().Str("receipt tx hash", hash.String()).Uint64("nonce", prop.DepositNonce).Str("chain", util.DomainIdToName[v.id]).Msgf("Voted")
	return nil
}

func (v *EVMVoter) SubmitSignature(m *message.Message, destChainId *big.Int, destBridgeAddress *common.Address) error {
	signatures, err := v.GetSignatures(m)
	if err != nil {
		return err
	}

	threshold, err := v.signatureContract.GetThreshold(m.Destination)
	if err != nil {
		return err
	}

	if len(signatures) >= int(threshold) {
		log.Warn().Str("chain", util.DomainIdToName[v.id]).Msgf("signatures length %v >= threshold %v, skip SubmitSignature", len(signatures), int(threshold))
		return errors.New(util.OVERTHRESHOLD)
	}

	privKey := v.client.PrivateKey()

	//chainId, _ := v.client.ChainID(context.TODO())
	log.Debug().Msgf("signer address %v, chainID: %v", crypto.PubkeyToAddress(privKey.PublicKey).Hex(), destChainId)

	name := "PermitBridge"
	version := "1.0"
	domainId := m.Source
	depositNonce := m.DepositNonce
	resourceId := m.ResourceId
	data := m.Data

	log.Debug().Msgf("[Domain] name: %v, version: %v, chainId: %v, verifyingContract: %v", name, version, destChainId, destBridgeAddress.String())

	log.Debug().Msgf("[Message] domainID: %v, depositNonce: %v, resourceID: %v, data: %v", domainId, depositNonce, hex.EncodeToString(resourceId[:]), hex.EncodeToString(data))

	typedData := &apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				apitypes.Type{Name: "name", Type: "string"},
				apitypes.Type{Name: "version", Type: "string"},
				apitypes.Type{Name: "chainId", Type: "uint256"},
				apitypes.Type{Name: "verifyingContract", Type: "address"},
			},
			"PermitBridge": {
				apitypes.Type{Name: "domainID", Type: "uint8"},
				apitypes.Type{Name: "depositNonce", Type: "uint64"},
				apitypes.Type{Name: "resourceID", Type: "bytes32"},
				apitypes.Type{Name: "data", Type: "bytes"}}},
		PrimaryType: "PermitBridge",
		Domain: apitypes.TypedDataDomain{
			Name:              name,
			Version:           version,
			ChainId:           math.NewHexOrDecimal256(destChainId.Int64()),
			VerifyingContract: destBridgeAddress.String()},
		Message: apitypes.TypedDataMessage{
			"domainID":     math.NewHexOrDecimal256(int64(domainId)),
			"depositNonce": math.NewHexOrDecimal256(int64(depositNonce)),
			"resourceID":   resourceId[:],
			"data":         data,
		}}
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return err
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	sighash := crypto.Keccak256(rawData)

	log.Debug().Msgf("rawData: %x sighash: %x", rawData, sighash)
	sig, err := v.client.Sign(sighash)
	sig[64] += 27

	log.Debug().Msgf("SIGNATURE: %v", hex.EncodeToString(sig))

	for _, signature := range signatures {
		if bytes.Equal(signature, sig) {
			return errors.New("relayer already voted")
		}
	}

	// ----------------- after checked, execute

	for i := 0; i < consts.TxRetryLimit; i++ {
		hash, err := v.signatureContract.SubmitSignature(m.Source, m.Destination, m.DepositNonce, m.ResourceId, m.Data, sig, transactor.TransactOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "transaction failed on chain") {
				break
			}

			time.Sleep(consts.TxRetryInterval)
			continue
		} else {
			log.Info().Str("receipt tx hash", hash.String()).Str("chain", util.DomainIdToName[v.id]).Msgf("SubmitSignature")
			break
		}
	}

	return err
}

func (v *EVMVoter) GetSignatures(m *message.Message) ([][]byte, error) {
	for i := 0; i < consts.TxRetryLimit; i++ {
		data, err := v.signatureContract.GetSignatures(m.Source, m.Destination, m.DepositNonce, m.ResourceId, m.Data)

		if err != nil {
			time.Sleep(consts.TxRetryInterval)
			continue
		} else {
			return data, nil
		}
	}

	return nil, nil
}

func (v *EVMVoter) ProposalStatusShouldVoteProposals(m *message.Message) (bool, uint8, error) {
	pps, err := v.bridgeContract.GetProposal(m.Source, m.DepositNonce, m.ResourceId, m.Data)
	if err != nil {
		log.Error().Err(err)
		return false, 0, err
	}

	if pps.Status == message.ProposalStatusInactive || pps.Status == message.ProposalStatusActive {
		return true, pps.Status, nil
	}

	return false, pps.Status, nil
}

func (v *EVMVoter) VoteProposals(m *message.Message, signatures [][]byte, flag *big.Int) error {
	pps, err := v.bridgeContract.GetProposal(m.Source, m.DepositNonce, m.ResourceId, m.Data)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	if pps.Status != message.ProposalStatusInactive && pps.Status != message.ProposalStatusActive {
		log.Warn().Str("chain", util.DomainIdToName[v.id]).
			Uint8("source", m.Source).
			Uint8("destination", m.Destination).
			Str("depositNonce", strconv.FormatUint(m.DepositNonce, 10)).
			Str("resourceID", hexutil.Encode(m.ResourceId[:])).
			Msgf("status %v can not VoteProposals, skipped", message.StatusMap[pps.Status])
		return nil
	}

	// ----------------- after checked, execute

	log.Info().Str("chain", util.DomainIdToName[v.id]).Int("flag", flag.Sign()).Msgf("VoteProposals message: %v", m.String())

	for i := 0; i < consts.TxRetryLimit; i++ {
		hash, err := v.bridgeContract.VoteProposals(m.Source, m.DepositNonce, m.ResourceId, m.Data, signatures, transactor.TransactOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "transaction failed on chain") {
				break
			}

			time.Sleep(consts.TxRetryInterval)
			continue
		} else {
			log.Info().Str("receipt tx hash", hash.String()).Str("chain", util.DomainIdToName[v.id]).Msgf("VoteProposals")
			break
		}
	}

	v.CheckAndExecuteAirDrop(*m)

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

func (v *EVMVoter) ChainID() (*big.Int, error) {
	return v.client.ChainID(context.TODO())
}

func (v *EVMVoter) BridgeContractAddress() *common.Address {
	return v.bridgeContract.ContractAddress()
}
