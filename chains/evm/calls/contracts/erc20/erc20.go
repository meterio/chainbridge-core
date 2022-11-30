package erc20

import (
	"github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls/consts"
	"github.com/rs/zerolog/log"
)

type ERC20Contract struct {
	contracts.Contract
}

func NewERC20Contract(
	client calls.ContractCallerDispatcher,
	erc20ContractAddress common.Address,
	transactor transactor.Transactor,
) *ERC20Contract {
	a, _ := abi.JSON(strings.NewReader(consts.ERC20PresetMinterPauserABI))
	b := common.FromHex(consts.ERC20PresetMinterPauserBin)
	return &ERC20Contract{contracts.NewContract(erc20ContractAddress, a, b, client, transactor)}
}

func (c *ERC20Contract) GetBalance(address common.Address) (*big.Int, error) {
	log.Debug().Msgf("Getting balance for %s", address.String())
	res, err := c.CallContract("balanceOf", address)
	if err != nil {
		return nil, err
	}
	b := abi.ConvertType(res[0], new(big.Int)).(*big.Int)
	return b, nil
}

func (c *ERC20Contract) MintTokens(
	to common.Address,
	amount *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Minting %s tokens to %s", amount.String(), to.String())
	return c.ExecuteTransaction("mint", opts, to, amount)
}

func (c *ERC20Contract) Transfer(
	to common.Address,
	amount *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Transfer %s tokens to %s", amount.String(), to.String())
	return c.ExecuteTransaction("transfer", opts, to, amount)
}

func (c *ERC20Contract) ApproveTokens(
	target common.Address,
	amount *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Approving %s tokens for %s", target.String(), amount.String())
	return c.ExecuteTransaction("approve", opts, target, amount)
}

func (c *ERC20Contract) DefaultAdminRole() ([32]byte, error) {
	res, err := c.CallContract("DEFAULT_ADMIN_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *ERC20Contract) MinterRole() ([32]byte, error) {
	res, err := c.CallContract("MINTER_ROLE")
	if err != nil {
		return [32]byte{}, err
	}
	out := *abi.ConvertType(res[0], new([32]byte)).(*[32]byte)
	return out, nil
}

func (c *ERC20Contract) GetRoleMemberCount(role [32]byte) (*big.Int, error) {
	res, err := c.CallContract("getRoleMemberCount", role)
	if err != nil {
		return nil, err
	}

	out := abi.ConvertType(res[0], new(big.Int)).(*big.Int)

	return out, nil
}

func (c *ERC20Contract) GetRoleMember(role [32]byte, i int64) (common.Address, error) {
	index := &big.Int{}
	index.SetInt64(i)

	res, err := c.CallContract("getRoleMember", role, index)
	if err != nil {
		return common.Address{}, err
	}
	out := *abi.ConvertType(res[0], new(common.Address)).(*common.Address)
	return out, nil
}

func (c *ERC20Contract) AddMinter(
	minter common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Adding new minter %s", minter.String())
	role, err := c.MinterRole()
	if err != nil {
		return nil, err
	}
	return c.ExecuteTransaction("grantRole", opts, role, minter)
}

func (c *ERC20Contract) AddAdmin(
	admin common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Adding new admin %s", admin.String())
	role, err := c.DefaultAdminRole()
	if err != nil {
		return nil, err
	}
	return c.ExecuteTransaction("grantRole", opts, role, admin)
}

func (c *ERC20Contract) RemoveMinter(
	minter common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Revoke minter %s", minter.String())
	role, err := c.MinterRole()
	if err != nil {
		return nil, err
	}
	return c.ExecuteTransaction("revokeRole", opts, role, minter)
}

func (c *ERC20Contract) RemoveAdmin(
	admin common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Revoke admin %s", admin.String())
	role, err := c.DefaultAdminRole()
	if err != nil {
		return nil, err
	}
	return c.ExecuteTransaction("revokeRole", opts, role, admin)
}
