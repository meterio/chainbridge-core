package bridge

import (
	"fmt"
	callsUtil "github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var queryProposalCmd = &cobra.Command{
	Use:   "query-proposal",
	Short: "Query an inbound proposal",
	Long:  "The query-proposal subcommand queries an inbound proposal",
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
		return queryProposal(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
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
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Data, "data", "", "proposal metadata")
	cmd.Flags().StringVar(&ResourceID, "resource", "", "Resource ID to query")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Source domain ID of proposal")
	cmd.Flags().Uint64Var(&DepositNonce, "deposit-nonce", 0, "Deposit nonce of proposal")
	flags.MarkFlagsAsRequired(cmd, "bridge", "data", "domain", "deposit-nonce", "resource")
}

func init() {
	BindQueryProposalFlags(queryProposalCmd)
}

func ValidateQueryProposalFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address: %s", Bridge)
	}
	return nil
}

func ProcessQueryProposalFlags(cmd *cobra.Command, args []string) error {
	BridgeAddr = common.HexToAddress(Bridge)

	resourceIdBytes, err := hexutil.Decode(ResourceID)
	if err != nil {
		return err
	}

	ResourceIdBytesArr = callsUtil.SliceTo32Bytes(resourceIdBytes)

	DataBytes, err = hexutil.Decode(Data)
	if err != nil {
		return err
	}

	return nil
}

func queryProposal(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Querying proposal
Chain ID: %d
Deposit nonce: %d
Data: %s
Bridge address: %s`, DomainID, DepositNonce, Data, Bridge)

	proposalStatus, err := contract.GetProposal(DomainID, DepositNonce, ResourceIdBytesArr, DataBytes)
	if err != nil {
		return err
	}
	log.Info().Msgf("Proposal: %v", proposalStatus.String())
	return nil
}
