package signatures

import (
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"math/big"
	"strings"
)

type SignaturesContract struct {
	contracts.Contract
}

func NewSignaturesContract(
	client calls.ContractCallerDispatcher,
	contractAddress common.Address,
	transactor transactor.Transactor,
) *SignaturesContract {
	a, _ := abi.JSON(strings.NewReader(consts.SignaturesABI))
	b := common.FromHex(consts.SignaturesBin)
	return &SignaturesContract{
		contracts.NewContract(contractAddress, a, b, client, transactor),
	}
}

type Signature struct {
	OriginDomainID      uint8
	DestinationDomainID uint8
	DestinationBridge   common.Address
	DepositNonce        uint64
	ResourceID          [32]byte
	Data                []byte
	Signature           []byte
}

//SubmitSignature
//uint8 originDomainID,
//uint8 destinationDomainID,
//address destinationBridge,
//uint64 depositNonce,
//bytes32 resourceID,
//bytes calldata data,
//bytes calldata signature
func (c *SignaturesContract) SubmitSignature(
	originDomainID uint8,
	destinationDomainID uint8,
	destinationBridge common.Address,
	depositNonce uint64,
	resourceID [32]byte,
	data []byte,
	signature []byte,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Info().Msgf("SubmitSignature: originDomainID %v, destinationDomainID %v, destinationBridge %v, depositNonce %v, resourceID %x", originDomainID, destinationDomainID, destinationBridge, depositNonce, resourceID)
	return c.ExecuteTransaction(
		"submitSignature",
		opts,
		originDomainID,
		destinationDomainID,
		destinationBridge,
		depositNonce,
		resourceID,
		data,
		signature,
	)
}

//GetSignatures
//uint8 domainID,
//uint64 depositNonce,
//bytes32 resourceID,
//bytes calldata data
func (c *SignaturesContract) GetSignatures(
	domainID uint8,
	depositNonce uint64,
	resourceID [32]byte,
	data []byte,
) ([][]byte, error) {
	res, err := c.CallContract("getSignatures", domainID, depositNonce, resourceID, data)
	if err != nil {
		return nil, err
	}

	out := *abi.ConvertType(res[0], new([][]byte)).(*[][]byte)
	return out, nil
}

func (c *SignaturesContract) CheckSignature(
	domainID uint8,
	destinationDomainID uint8,
	destinationBridge common.Address,
	depositNonce uint64,
	resourceID [32]byte,
	data []byte,
	signature []byte,
) (bool, error) {
	res, err := c.CallContract("checkSignature", domainID, destinationDomainID, destinationBridge, depositNonce,
		resourceID, data, signature)
	if err != nil {
		return false, err
	}

	out := abi.ConvertType(res[0], new(bool)).(*bool)
	return *out, nil
}

func (c *SignaturesContract) DefaultAdminRole() ([32]byte, error) {
	res, err := c.CallContract("DEFAULT_ADMIN_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *SignaturesContract) RelayerRole() ([32]byte, error) {
	res, err := c.CallContract("RELAYER_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *SignaturesContract) MinterRole() ([32]byte, error) {
	res, err := c.CallContract("MINTER_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *SignaturesContract) GetRoleMemberCount(role [32]byte) (*big.Int, error) {
	res, err := c.CallContract("getRoleMemberCount", role)
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)

	return out, nil
}

func (c *SignaturesContract) GetRoleMember(role [32]byte, i int64) (common.Address, error) {
	index := &big.Int{}
	index.SetInt64(i)

	res, err := c.CallContract("getRoleMember", role, index)
	if err != nil {
		return common.Address{}, err
	}
	out := *abi.ConvertType(res[0], new(common.Address)).(*common.Address)
	return out, nil
}

func (c *SignaturesContract) GetThreshold(domain uint8) (uint8, error) {
	log.Debug().Msg("Getting threshold")
	res, err := c.CallContract("_relayerThreshold", domain)
	if err != nil {
		return 0, err
	}
	out := *abi.ConvertType(res[0], new(uint8)).(*uint8)
	return out, nil
}

func (c *SignaturesContract) HasVote(sig []byte) (bool, error) {
	log.Debug().Msg("Has Vote?")
	res, err := c.CallContract("hasVote", sig)
	if err != nil {
		return false, err
	}
	out := *abi.ConvertType(res[0], new(bool)).(*bool)
	return out, nil
}

func (c *SignaturesContract) SetThresholdInput(
	destinationDomainID uint8,
	threshold uint64,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting threshold %d", threshold)
	return c.ExecuteTransaction(
		"adminChangeRelayerThreshold",
		opts,
		destinationDomainID,
		big.NewInt(0).SetUint64(threshold),
	)
}

func (c *SignaturesContract) GrantRole(
	role [32]byte,
	account common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	//log.Debug().Msgf("Setting threshold %d", threshold)
	return c.ExecuteTransaction(
		"grantRole",
		opts,
		role, account,
	)
}

func (c *SignaturesContract) AdminSetDestChainId(
	destinationDomainID uint8,
	chainId uint64,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	//log.Debug().Msgf("Setting threshold %d", threshold)
	return c.ExecuteTransaction(
		"adminSetDestChainId",
		opts,
		destinationDomainID, big.NewInt(int64(chainId)),
	)
}

func (c *SignaturesContract) GetDestChainId(
	destinationDomainID uint8,
) (*big.Int, error) {
	res, err := c.CallContract("destChainId", destinationDomainID)
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)
	//out := *abi.ConvertType(res[0], new(big.Int)).(*big.Int)
	return out, nil
}
