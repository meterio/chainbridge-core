package erc20

import (
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/consts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"strings"
)

type ERC20HandlerContract struct {
	contracts.Contract
}

func NewERC20HandlerContract(
	client calls.ContractCallerDispatcher,
	erc20HandlerContractAddress common.Address,
	t transactor.Transactor,
) *ERC20HandlerContract {
	a, _ := abi.JSON(strings.NewReader(consts.ERC20HandlerABI))
	b := common.FromHex(consts.ERC20HandlerBin)
	return &ERC20HandlerContract{contracts.NewContract(erc20HandlerContractAddress, a, b, client, t)}
}

func (c *ERC20HandlerContract) IsNative(address common.Address) (bool, error) {
	log.Debug().Msgf("Check Native for %s", address.String())
	res, err := c.CallContract("isNative", address)
	if err != nil {
		return false, err
	}
	b := abi.ConvertType(res[0], new(bool)).(bool)
	return b, nil
}
