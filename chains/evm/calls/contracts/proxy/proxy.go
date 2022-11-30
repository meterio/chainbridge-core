package proxy

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/consts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/rs/zerolog/log"
)

type ProxyContract struct {
	contracts.Contract
}

func NewProxyContract(
	client calls.ContractCallerDispatcher,
	proxyContractAddress common.Address,
	transactor transactor.Transactor,
) *ProxyContract {
	a, _ := abi.JSON(strings.NewReader(consts.ProxyABI))
	b := common.FromHex(consts.ProxyBin)
	return &ProxyContract{contracts.NewContract(proxyContractAddress, a, b, client, transactor)}
}

func (c *ProxyContract) ChangeAdmin(
	adminAddr common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("change to admin: %s", adminAddr.String())
	return c.ExecuteTransaction(
		"changeAdmin",
		opts,
		adminAddr,
	)
}

func (c *ProxyContract) UpgradeTo(
	newImplementation common.Address,
	opts transactor.TransactOptions,
) (*common.Hash, error) {
	log.Debug().Msgf("new Implementation: %s", newImplementation.String())
	return c.ExecuteTransaction(
		"upgradeTo",
		opts,
		newImplementation,
	)
}
