// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ChainSafe/chainbridge-core/util"
	ethereum "github.com/ethereum/go-ethereum"

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
	"github.com/ChainSafe/chainbridge-core/lvldb"
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
	SubmitSignature(originDomainID uint8, destinationDomainID uint8, destinationBridge common.Address, depositNonce uint64, resourceID [32]byte, data []byte, signature []byte, opts transactor.TransactOptions) (*common.Hash, error)

	GetThreshold(domain uint8) (uint8, error)
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
	delayVoteProposals   *big.Int
}

// NewVoterWithSubscription creates an instance of EVMVoter that votes for
// proposals on chain.
//
// It is created with a pending proposal subscription that listens to
// pending voteProposal transactions and avoids wasting gas on sending votes
// for transactions that will fail.
// Currently, officially supported only by Geth nodes.
func NewVoterWithSubscription(db *lvldb.LVLDB, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, id uint8, delayVoteProposals *big.Int) (*EVMVoter, error) {
	voter := &EVMVoter{
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		db:                   db,
		delayVoteProposals:   delayVoteProposals,
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
func NewVoter(db *lvldb.LVLDB, mh MessageHandler, client ChainClient, bridgeContract BridgeContract, signatureContract SignatureContract, id uint8, delayVoteProposals *big.Int) *EVMVoter {
	return &EVMVoter{
		mh:                   mh,
		client:               client,
		bridgeContract:       bridgeContract,
		signatureContract:    signatureContract,
		pendingProposalVotes: make(map[common.Hash]uint8),
		id:                   id,
		db:                   db,
		delayVoteProposals:   delayVoteProposals,
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

	log.Info().Str("tx hash", hash.String()).Uint64("nonce", prop.DepositNonce).Msgf("Voted")
	return nil
}

func (v *EVMVoter) GetSignature(chainId int64, domainId int64, depositNonce int64, resourceId []byte, data []byte) error {
	chainId = 3
	domainId = 5
	depositNonce = 22
	//privKey := v.client.PrivateKey()
	resourceId, err := hex.DecodeString("00000000000000000000008a419ef4941355476cf04933e90bf3bbf2f7381400")
	if err != nil {
		return err
	}
	data, err = hex.DecodeString("00000000000000000000000000000000000000000000000000194cb424068e000000000000000000000000000000000000000000000000000000000000000014551b6e92f7443e63ec2d0c43471de9574e834169")
	if err != nil {
		return err
	}
	privKey, err := crypto.HexToECDSA("b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659")
	if err != nil {
		return err
	}
	_ = privKey
	//cid, _ := v.client.ChainID(context.TODO())
	//log.Info().Msgf("signer address %v, chainID: %v", crypto.PubkeyToAddress(privKey.PublicKey).Hex(), cid.Int64())

	name := "PermitBridge"
	version := "1.0"
	verifyingContract := common.HexToAddress("4eBc9d4Dd56278a4a8480a21f27CBA345668bdc4") // v.bridgeContract.ContractAddress()

	log.Info().Msgf("name: %v, version: %v, chainId: %v, verifyingContract: %v", name, version, chainId, verifyingContract.String())

	log.Info().Msgf("domainID: %v, depositNonce: %v, resourceID: %v, data: %v", domainId, depositNonce, hex.EncodeToString(resourceId), hex.EncodeToString(data))

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
			ChainId:           math.NewHexOrDecimal256(chainId),
			VerifyingContract: verifyingContract.String()},
		Message: apitypes.TypedDataMessage{
			"domainID":     math.NewHexOrDecimal256(domainId),
			"depositNonce": math.NewHexOrDecimal256(depositNonce),
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

	sig, err := v.client.Sign(sighash)

	// Convert to Ethereum signature format with 'recovery id' v at the end.
	//vSuffix := []byte{0x1c}
	//copy(sig, sig[1:])
	sig[64] = 0x1c
	//return signature, nil
	//sig = append(sig, vSuffix...)

	//signer := beecrypto.NewDefaultSigner(privKey)
	//sig, err := signer.Sign(sighash)
	if err != nil {
		return err
	}

	log.Info().Msgf("SIGNATURE: %v", hex.EncodeToString(sig))
	return err
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
		log.Info().Msgf("signatures length >= threshold, skip SubmitSignature")
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

	hash, err := v.signatureContract.SubmitSignature(m.Source, m.Destination, *destBridgeAddress, m.DepositNonce, m.ResourceId, m.Data, sig, transactor.TransactOptions{})
	if err != nil {
		return err
	}
	log.Info().Str("tx hash", hash.String()).Msgf("SubmitSignature")

	err = v.saveMessage(*m)
	if err != nil {
		log.Error().Err(err)
		return err
	}

	return err
}

func (v *EVMVoter) GetSignatures(m *message.Message) ([][]byte, error) {
	data, err := v.signatureContract.GetSignatures(m.Source, m.DepositNonce, m.ResourceId, m.Data)
	if err != nil {
		return [][]byte{}, err
	}
	return data, nil
}

func (v *EVMVoter) ProposalStatusInactive(m *message.Message) (bool, error) {
	pps, err := v.bridgeContract.GetProposal(m.Source, m.DepositNonce, m.ResourceId, m.Data)
	if err != nil {
		return false, err
	}

	if pps.Status != message.ProposalStatusInactive {
		log.Info().Msgf("Proposal Status not Inactive, skip VoteProposals")
		return false, nil
	}

	return true, nil
}

func (v *EVMVoter) VoteProposals(m *message.Message, signatures [][]byte) error {
	<-time.After(time.Second * time.Duration(v.delayVoteProposals.Int64()))

	statusInactive, err := v.ProposalStatusInactive(m)
	if err != nil {
		return err
	}

	if !statusInactive {
		log.Info().Msgf("Proposal Status not Inactive, skip VoteProposals")
		return nil
	}

	//log.Info().Msgf("VoteProposals message: %v", m)

	hash, err := v.bridgeContract.VoteProposals(m.Source, m.DepositNonce, m.ResourceId, m.Data, signatures, transactor.TransactOptions{})
	if err != nil {
		return err
	}
	log.Info().Str("tx hash", hash.String()).Msgf("VoteProposals")

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

	key := []byte{m.Source, 0x00, m.Destination, 0x00, byte(m.DepositNonce)}

	log.Debug().Msgf("saveMessage db.SetByKey %x", key)
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

func (v *EVMVoter) ChainID() (*big.Int, error) {
	return v.client.ChainID(context.TODO())
}

func (v *EVMVoter) BridgeContractAddress() *common.Address {
	return v.bridgeContract.ContractAddress()
}
