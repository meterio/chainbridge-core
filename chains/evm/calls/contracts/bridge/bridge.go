package bridge

import (
	"bytes"
	"math/big"
	"strconv"
	"strings"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/deposit"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ChainSafe/chainbridge-core/chains/evm/voter/proposal"
	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
)

type BridgeContract struct {
	contracts.Contract
}

func NewBridgeContract(
	client calls.ContractCallerDispatcher,
	bridgeContractAddress common.Address,
	transactor transactor.Transactor,
) *BridgeContract {
	a, _ := abi.JSON(strings.NewReader(consts.BridgeABI))
	b := common.FromHex(consts.BridgeBin)
	return &BridgeContract{contracts.NewContract(bridgeContractAddress, a, b, client, transactor)}
}

func (c *BridgeContract) AddRelayer(
	relayerAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Adding new relayer %s", relayerAddr.String())
	return c.ExecuteTransaction(
		"adminAddRelayer",
		opts,
		relayerAddr,
	)
}

func (c *BridgeContract) RemoveRelayer(
	relayerAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Remove relayer %s", relayerAddr.String())
	return c.ExecuteTransaction(
		"adminRemoveRelayer",
		opts,
		relayerAddr,
	)
}

func (c *BridgeContract) RenounceAdmin(
	adminAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("renounce admin: %s", adminAddr.String())
	return c.ExecuteTransaction(
		"renounceAdmin",
		opts,
		adminAddr,
	)
}

func (c *BridgeContract) AdminSetGenericResource(
	handler common.Address,
	rID types.ResourceID,
	addr common.Address,
	depositFunctionSig [4]byte,
	depositerOffset *big.Int,
	executeFunctionSig [4]byte,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting generic resource %s", hexutil.Encode(rID[:]))
	return c.ExecuteTransaction(
		"adminSetGenericResource",
		opts,
		handler, rID, addr, depositFunctionSig, depositerOffset, executeFunctionSig,
	)
}

func (c *BridgeContract) AdminSetNativeResource(
	handler common.Address,
	rID types.ResourceID,
	addr common.Address,
	depositFunctionSig [4]byte,
	depositerOffset *big.Int,
	executeFunctionSig [4]byte,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting native resource %s", hexutil.Encode(rID[:]))
	return c.ExecuteTransaction(
		"adminSetNativeResource",
		opts,
		handler, rID, addr, depositFunctionSig, depositerOffset, executeFunctionSig,
	)
}

func (c *BridgeContract) AdminSetResource(
	handlerAddr common.Address,
	rID types.ResourceID,
	targetContractAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting resource %s", hexutil.Encode(rID[:]))
	return c.ExecuteTransaction(
		"adminSetResource",
		opts,
		handlerAddr, rID, targetContractAddr,
	)
}

func (c *BridgeContract) AdminRemoveResourceId(
	rID types.ResourceID,
	targetContractAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting resource %s", hexutil.Encode(rID[:]))
	return c.ExecuteTransaction(
		"adminRemoveResourceId",
		opts,
		rID, targetContractAddr,
	)
}

func (c *BridgeContract) AdminSetWtoken(
	rID types.ResourceID,
	targetContractAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting wtoken %s", hexutil.Encode(rID[:]))
	return c.ExecuteTransaction(
		"adminSetNative",
		opts,
		rID, targetContractAddr, true,
	)
}

func (c *BridgeContract) SetDepositNonce(
	domainId uint8,
	depositNonce uint64,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting deposit nonce %d for %d", depositNonce, domainId)
	return c.ExecuteTransaction(
		"adminSetDepositNonce",
		opts,
		domainId, depositNonce,
	)
}

func (c *BridgeContract) SetThresholdInput(
	threshold uint64,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting threshold %d", threshold)
	return c.ExecuteTransaction(
		"adminChangeRelayerThreshold",
		opts,
		big.NewInt(0).SetUint64(threshold),
	)
}

func (c *BridgeContract) SetBurnableInput(
	handlerAddr common.Address,
	tokenContractAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting burnable input for %s", tokenContractAddr.String())
	return c.ExecuteTransaction(
		"adminSetBurnable",
		opts,
		handlerAddr, tokenContractAddr,
	)
}

func (c *BridgeContract) deposit(
	resourceID types.ResourceID,
	destDomainID uint8,
	data []byte,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	feeData := []byte{0x00}

	return c.ExecuteTransaction(
		"deposit",
		opts,
		destDomainID, resourceID, data, feeData,
	)
}

func (c *BridgeContract) Erc20Deposit(
	recipient common.Address,
	amount *big.Int,
	resourceID types.ResourceID,
	destDomainID uint8,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Info().
		Str("recipient", recipient.String()).
		Str("resourceID", hexutil.Encode(resourceID[:])).
		Str("amount", amount.String()).
		Msgf("ERC20 deposit")
	data := deposit.ConstructErc20DepositData(recipient.Bytes(), amount)
	txHash, err := c.deposit(resourceID, destDomainID, data, opts)
	if err != nil {
		log.Error().Err(err)
		return nil, err
	}
	return txHash, err
}

func (c *BridgeContract) Erc721Deposit(
	tokenId *big.Int,
	metadata string,
	recipient common.Address,
	resourceID types.ResourceID,
	destDomainID uint8,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().
		Str("recipient", recipient.String()).
		Str("resourceID", hexutil.Encode(resourceID[:])).
		Str("tokenID", tokenId.String()).
		Msgf("ERC721 deposit")
	data := deposit.ConstructErc721DepositData(recipient.Bytes(), tokenId, []byte(metadata))
	txHash, err := c.deposit(resourceID, destDomainID, data, opts)
	if err != nil {
		log.Error().Err(err)
		return nil, err
	}
	return txHash, err
}

func (c *BridgeContract) GenericDeposit(
	metadata []byte,
	resourceID types.ResourceID,
	destDomainID uint8,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().
		Str("resourceID", hexutil.Encode(resourceID[:])).
		Msgf("Generic deposit")
	data := deposit.ConstructGenericDepositData(metadata)
	txHash, err := c.deposit(resourceID, destDomainID, data, opts)
	if err != nil {
		log.Error().Err(err)
		return nil, err
	}
	return txHash, err
}

func (c *BridgeContract) ExecuteProposal(
	proposal *proposal.Proposal,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().
		Str("depositNonce", strconv.FormatUint(proposal.DepositNonce, 10)).
		Str("resourceID", hexutil.Encode(proposal.ResourceId[:])).
		Str("handler", proposal.HandlerAddress.String()).
		Msgf("Execute proposal")
	return c.ExecuteTransaction(
		"executeProposal",
		opts,
		proposal.Source, proposal.DepositNonce, proposal.Data, proposal.ResourceId, true,
	)
}

func (c *BridgeContract) VoteProposal(
	proposal *proposal.Proposal,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Info().
		Str("depositNonce", strconv.FormatUint(proposal.DepositNonce, 10)).
		Str("resourceID", hexutil.Encode(proposal.ResourceId[:])).
		Str("handler", proposal.HandlerAddress.String()).
		Msgf("Vote proposal")
	return c.ExecuteTransaction(
		"voteProposal",
		opts,
		proposal.Source, proposal.DepositNonce, proposal.ResourceId, proposal.Data,
	)
}

func (c *BridgeContract) VoteProposals(
	domainID uint8,
	depositNonce uint64,
	resourceID [32]byte,
	data []byte,
	signatures [][]byte,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Info().
		Str("domainID", strconv.Itoa(int(domainID))).
		Str("depositNonce", strconv.FormatUint(depositNonce, 10)).
		Str("resourceID", hexutil.Encode(resourceID[:])).
		Msgf("VoteProposals")
	return c.ExecuteTransaction(
		"voteProposals",
		opts,
		domainID, depositNonce, resourceID, data, signatures,
	)
}

func (c *BridgeContract) SimulateVoteProposal(proposal *proposal.Proposal) error {
	log.Debug().
		Str("depositNonce", strconv.FormatUint(proposal.DepositNonce, 10)).
		Str("resourceID", hexutil.Encode(proposal.ResourceId[:])).
		Str("handler", proposal.HandlerAddress.String()).
		Msgf("Simulate vote proposal")
	_, err := c.CallContract(
		"voteProposal",
		proposal.Source, proposal.DepositNonce, proposal.ResourceId, proposal.Data,
	)
	return err
}

func (c *BridgeContract) Pause(opts transactor.TransactOptions) (*common.Hash, error) {
	log.Debug().Msg("Pause transfers")
	return c.ExecuteTransaction(
		"adminPauseTransfers",
		opts,
	)
}

func (c *BridgeContract) Unpause(opts transactor.TransactOptions) (*common.Hash, error) {
	log.Debug().Msg("Unpause transfers")
	return c.ExecuteTransaction(
		"adminUnpauseTransfers",
		opts,
	)
}

func (c *BridgeContract) Withdraw(
	handlerAddress,
	tokenAddress,
	recipientAddress common.Address,
	amountOrTokenId *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	// @dev withdrawal data should include:
	// tokenAddress
	// recipientAddress
	// realAmount
	data := bytes.Buffer{}
	data.Write(common.LeftPadBytes(tokenAddress.Bytes(), 32))
	data.Write(common.LeftPadBytes(recipientAddress.Bytes(), 32))
	data.Write(common.LeftPadBytes(amountOrTokenId.Bytes(), 32))

	return c.ExecuteTransaction("adminWithdraw", opts, handlerAddress, data.Bytes())
}

func (c *BridgeContract) GetThreshold() (uint8, error) {
	log.Debug().Msg("Getting threshold")
	res, err := c.CallContract("_relayerThreshold")
	if err != nil {
		return 0, err
	}
	out := *abi.ConvertType(res[0], new(uint8)).(*uint8)
	return out, nil
}

func (c *BridgeContract) GetFee() (*big.Int, error) {
	log.Debug().Msg("Getting fee")
	res, err := c.CallContract("_fee_")
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)
	return out, nil
}

func (c *BridgeContract) GetFeeReserve() (*big.Int, error) {
	log.Debug().Msg("Getting fee reserve")
	res, err := c.CallContract("_feeReserve")
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)
	return out, nil
}

func (c *BridgeContract) IsRelayer(relayerAddress common.Address) (bool, error) {
	log.Debug().Msgf("Getting is %s a relayer", relayerAddress.String())
	res, err := c.CallContract("isRelayer", relayerAddress)
	if err != nil {
		return false, err
	}
	out := abi.ConvertType(res[0], new(bool)).(*bool)
	return *out, nil
}

func (c *BridgeContract) GetProposal(source uint8, depositNonce uint64, resourceId types.ResourceID, data []byte) (message.ProposalStatus, error) {
	log.Debug().
		Str("source", strconv.FormatUint(uint64(source), 10)).
		Str("depositNonce", strconv.FormatUint(depositNonce, 10)).
		Str("resourceID", hexutil.Encode(resourceId[:])).
		Msg("Getting proposal")
	res, err := c.CallContract("getProposal", source, depositNonce, resourceId, data)
	if err != nil {
		return message.ProposalStatus{}, err
	}
	out := *abi.ConvertType(res[0], new(message.ProposalStatus)).(*message.ProposalStatus)
	return out, nil
}

func (c *BridgeContract) ProposalStatus(p *proposal.Proposal) (message.ProposalStatus, error) {
	log.Debug().
		Str("depositNonce", strconv.FormatUint(p.DepositNonce, 10)).
		Str("resourceID", hexutil.Encode(p.ResourceId[:])).
		Str("handler", p.HandlerAddress.String()).
		Msg("Getting proposal status")
	res, err := c.CallContract("getProposal", p.Source, p.DepositNonce, p.ResourceId, p.Data)
	if err != nil {
		return message.ProposalStatus{}, err
	}
	out := *abi.ConvertType(res[0], new(message.ProposalStatus)).(*message.ProposalStatus)
	return out, nil
}

func (c *BridgeContract) IsProposalVotedBy(by common.Address, p *proposal.Proposal) (bool, error) {
	log.Debug().
		Str("depositNonce", strconv.FormatUint(p.DepositNonce, 10)).
		Str("resourceID", hexutil.Encode(p.ResourceId[:])).
		Str("handler", p.HandlerAddress.String()).
		Msgf("Getting is proposal voted by %s", by.String())
	res, err := c.CallContract("_hasVotedOnProposal", idAndNonce(p.Source, p.DepositNonce), p.GetDataHash(), by)
	if err != nil {
		return false, err
	}
	out := *abi.ConvertType(res[0], new(bool)).(*bool)
	return out, nil
}

func (c *BridgeContract) GetHandlerAddressForResourceID(
	resourceID types.ResourceID,
) (common.Address, error) {
	log.Debug().Msgf("Getting handler address for resource %s", hexutil.Encode(resourceID[:]))
	res, err := c.CallContract("_resourceIDToHandlerAddress", resourceID)
	if err != nil {
		return common.Address{}, err
	}
	out := *abi.ConvertType(res[0], new(common.Address)).(*common.Address)
	return out, nil
}

func idAndNonce(srcId uint8, nonce uint64) *big.Int {
	var data []byte
	data = append(data, big.NewInt(int64(nonce)).Bytes()...)
	data = append(data, uint8(srcId))
	return big.NewInt(0).SetBytes(data)
}

func (c *BridgeContract) DefaultAdminRole() ([32]byte, error) {
	res, err := c.CallContract("DEFAULT_ADMIN_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *BridgeContract) MinterRole() ([32]byte, error) {
	res, err := c.CallContract("MINTER_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *BridgeContract) RelayerRole() ([32]byte, error) {
	res, err := c.CallContract("RELAYER_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *BridgeContract) GetRoleMemberCount(role [32]byte) (*big.Int, error) {
	res, err := c.CallContract("getRoleMemberCount", role)
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)

	return out, nil
}

func (c *BridgeContract) GetRoleMember(role [32]byte, i int64) (common.Address, error) {
	index := &big.Int{}
	index.SetInt64(i)

	res, err := c.CallContract("getRoleMember", role, index)
	if err != nil {
		return common.Address{}, err
	}
	out := *abi.ConvertType(res[0], new(common.Address)).(*common.Address)
	return out, nil
}

func (c *BridgeContract) GrantRole(
	role [32]byte,
	account common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Grant Role role %x to %s", role, account.String())
	return c.ExecuteTransaction(
		"grantRole",
		opts,
		role,
		account,
	)
}

func (c *BridgeContract) RevokeRole(
	role [32]byte,
	account common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("revoke role %x from %s", role, account.String())
	return c.ExecuteTransaction(
		"revokeRole",
		opts,
		role,
		account,
	)
}

func (c *BridgeContract) SetFee(
	newFee *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Set Fee for %d", newFee)
	return c.ExecuteTransaction(
		"adminSetFee",
		opts,
		newFee,
	)
}

func (c *BridgeContract) TransferFee(
	account common.Address,
	amount *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Transfer Fee %d to %x", amount, account)
	return c.ExecuteTransaction(
		"transferFee",
		opts,
		account,
		amount,
	)
}

func (c *BridgeContract) SetSpecialFee(
	fromDomainID uint8,
	_specialFee *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting SpecialFee %d for %d", _specialFee, fromDomainID)
	return c.ExecuteTransaction(
		"adminSetSpecialFee",
		opts,
		fromDomainID,
		_specialFee,
	)
}
