package signature

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	callsUtil "github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var queryProposalCmd = &cobra.Command{
	Use:   "query-proposal",
	Short: "Query a relay chain proposal",
	Long:  "The query-proposal subcommand queries a relay chain proposal",
	PreRun: func(cmd *cobra.Command, args []string) {
		logger.LoggerMetadata(cmd.Name(), cmd.Flags())
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return util.CallPersistentPreRun(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := initialize.InitializeClient(url, senderKeyPair)
		if err != nil {
			return err
		}
		t, err := initialize.InitializeTransactor(gasPrice, evmtransaction.NewTransaction, c, prepare)
		if err != nil {
			return err
		}
		return queryProposal(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateQueryProposalFlags(cmd, args)
		if err != nil {
			return err
		}
		ProcessQueryProposalFlags(cmd, args)
		return nil
	},
}

func BindQueryProposalFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	cmd.Flags().StringVar(&ResourceID, "resource", "", "Resource ID to query")

	cmd.Flags().StringVar(&Data, "data", "", "proposal metadata")
	cmd.Flags().Uint8Var(&DomainID, "src-domain", 0, "Source domain ID of proposal")
	cmd.Flags().Uint8Var(&DestDomainID, "dest-domain", 0, "Dest domain ID of proposal")
	cmd.Flags().Uint64Var(&DepositNonce, "deposit-nonce", 0, "Deposit nonce of proposal")
	flags.MarkFlagsAsRequired(cmd, "signature", "data", "src-domain", "dest-domain", "deposit-nonce")
}

func init() {
	BindQueryProposalFlags(queryProposalCmd)
}

func ValidateQueryProposalFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid signature address: %s", Signature)
	}
	return nil
}

func ProcessQueryProposalFlags(cmd *cobra.Command, args []string) error {
	SignatureAddr = common.HexToAddress(Signature)

	resourceIdBytes, err := hexutil.Decode(ResourceID)
	if err != nil {
		return err
	}

	ResourceIdBytesArr = callsUtil.SliceTo32Bytes(resourceIdBytes)

	DataBytes, err = hexutil.Decode(Data)
	if err != nil {
		return err
	}

	dataHash := crypto.Keccak256Hash(DataBytes)
	//log.Info().Msgf("dataHash %x", dataHash)

	uint8Type, _ := abi.NewType("uint8", "uint8", nil)
	uint64Type, _ := abi.NewType("uint64", "uint64", nil)
	bytes32Type, _ := abi.NewType("bytes32", "bytes32", nil)

	arguments := abi.Arguments{
		{
			Type: uint8Type,
		},
		{
			Type: uint8Type,
		},
		{
			Type: uint64Type,
		},
		{
			Type: bytes32Type,
		},
		{
			Type: bytes32Type,
		},
	}

	bytes, err := arguments.Pack(
		DomainID,
		DestDomainID,
		DepositNonce,
		ResourceIdBytesArr,
		dataHash,
	)
	if err != nil {
		return err
	}

	depositHash := crypto.Keccak256Hash(bytes)

	copy(DepositHash[:], depositHash[:])

	return nil
}

func queryProposal(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	log.Debug().Msgf(`
Querying proposal
Domain ID: %d
Dest Domain ID: %d
Deposit nonce: %d
ResourceID: %s
Data: %s
Signature address: %s`, DomainID, DestDomainID, DepositNonce, ResourceID, Data, Signature)
	proposal, err := contract.QueryProposal(DepositHash)
	if err != nil {
		return err
	}

	signatures, err := contract.GetSignatures(DomainID, DestDomainID, DepositNonce, ResourceIdBytesArr, DataBytes)
	if err != nil {
		return err
	}

	log.Info().Msgf("Proposal: %v", proposal)
	if len(signatures) == 0 {
		log.Info().Msgf("Signatures: []")
	} else {
		log.Info().Msgf("Signatures:")

		for i, signature := range signatures {
			log.Info().Msgf("%v %#x", i, signature)
		}
	}

	return nil
}
