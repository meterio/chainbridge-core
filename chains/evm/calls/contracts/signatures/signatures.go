package signatures

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

type SignaturesContract struct {
	contracts.Contract
}

func NewSignaturesContract(
	client calls.ContractCallerDispatcher,
	contractAddress common.Address,
) *SignaturesContract {
	a, _ := abi.JSON(strings.NewReader(consts.SignaturesABI))
	b := common.FromHex(consts.SignaturesBin)
	return &SignaturesContract{
		contracts.NewContract(contractAddress, a, b, client, nil),
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
	log.Debug().Msgf("SubmitSignature: originDomainID %v, destinationDomainID %v, destinationBridge %v, depositNonce %v, resourceID %v", originDomainID, destinationDomainID, destinationBridge, depositNonce, resourceID)
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
