package generic

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/consts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"strings"
)

type GenericHandlerContract struct {
	contracts.Contract
}

func NewGenericHandlerContract(
	client calls.ContractCallerDispatcher,
	assetStoreContractAddress common.Address,
	transactor transactor.Transactor,
) *GenericHandlerContract {
	a, _ := abi.JSON(strings.NewReader(consts.GenericHandlerABI))
	b := common.FromHex(consts.GenericHandlerBin)
	return &GenericHandlerContract{contracts.NewContract(assetStoreContractAddress, a, b, client, transactor)}
}
