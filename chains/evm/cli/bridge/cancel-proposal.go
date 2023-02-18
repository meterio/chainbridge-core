package bridge

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	callsUtil "github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cancelProposalCmd = &cobra.Command{
	Use:   "cancel-proposal",
	Short: "Cancel an expired proposal",
	Long:  "The cancel-proposal subcommand cancels an expired proposal",
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
		return cancelProposal(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateCancelProposalFlags(cmd, args)
		if err != nil {
			return err
		}
		err = ProcessCancelProposalFlags(cmd, args)
		return nil
	},
}

func BindCancelProposalFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&DataHash, "data-hash", "", "Hash of proposal metadata")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of proposal to cancel")
	cmd.Flags().Uint64Var(&DepositNonce, "deposit-nonce", 0, "Deposit nonce of proposal to cancel")
	flags.MarkFlagsAsRequired(cmd, "bridge", "data-hash", "domain", "deposit-nonce")
}

func init() {
	BindCancelProposalFlags(cancelProposalCmd)
}

func ValidateCancelProposalFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address: %s", Bridge)
	}
	return nil
}

func ProcessCancelProposalFlags(cmd *cobra.Command, args []string) error {
	DataBytes = common.Hex2Bytes(DataHash)
	DataHashBytes = callsUtil.SliceTo32Bytes(DataBytes)
	BridgeAddr = common.HexToAddress(Bridge)
	return nil
}

func cancelProposal(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Cancel Proposal
Bridge address: %s
Domain ID: %d
Deposit nonce: %d
DataHash: %s
`, Bridge, DomainID, DepositNonce, DataHash)
	h, err := contract.CancelProposal(DomainID, DepositNonce, DataHashBytes, transactor.TransactOptions{GasLimit: gasLimit})
	if err != nil {
		log.Error().Err(err)
		return err
	}

	log.Info().Msgf("Cancel Proposal with transaction: %s", h.Hex())
	return nil
}
