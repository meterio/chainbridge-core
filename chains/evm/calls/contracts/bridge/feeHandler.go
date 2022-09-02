package bridge

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

type FeeHandlerContract struct {
	contracts.Contract
}

func NewFeeHandlerContract(
	client calls.ContractCallerDispatcher,
	feeHandlerContractAddress common.Address,
	t transactor.Transactor,
) *FeeHandlerContract {
	a, _ := abi.JSON(strings.NewReader(consts.FeeHandlerABI))
	b := common.FromHex(consts.FeeHandlerBin)
	return &FeeHandlerContract{contracts.NewContract(feeHandlerContractAddress, a, b, client, t)}
}

func (c *FeeHandlerContract) ChangeFee(
	newFee *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("ChangeFee for %d", newFee)
	return c.ExecuteTransaction(
		"changeFee",
		opts,
		newFee,
	)
}

func (c *FeeHandlerContract) SetSpecialFee(
	fromDomainID uint8,
	_specialFee *big.Int,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("Setting SpecialFee %d for %d", _specialFee, fromDomainID)
	return c.ExecuteTransaction(
		"setSpecialFee",
		opts,
		fromDomainID,
		_specialFee,
	)
}

func (c *FeeHandlerContract) RenounceAdmin(
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