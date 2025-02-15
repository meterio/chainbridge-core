package admin

import (
	"fmt"

	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/spf13/cobra"
)

var AdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Set of commands for executing various admin actions",
	Long:  "Set of commands for executing various admin actions",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		// fetch global flag values
		url, gasLimit, gasPrice, senderKeyPair, prepare, err = flags.GlobalFlagValues(cmd)
		if err != nil {
			return fmt.Errorf("could not get global flags: %v", err)
		}
		return nil
	},
}

func init() {
	AdminCmd.AddCommand(addAdminCmd)
	AdminCmd.AddCommand(getFeeCmd)
	AdminCmd.AddCommand(renounceAdminCmd)
	AdminCmd.AddCommand(changeAdminCmd)
	AdminCmd.AddCommand(transferFeeCmd)
	AdminCmd.AddCommand(upgradeImplementationCmd)
	AdminCmd.AddCommand(addRelayerCmd)
	AdminCmd.AddCommand(isRelayerCmd)
	AdminCmd.AddCommand(pauseCmd)
	AdminCmd.AddCommand(removeAdminCmd)
	AdminCmd.AddCommand(removeRelayerCmd)
	AdminCmd.AddCommand(setFeeCmd)
	AdminCmd.AddCommand(setSpecialFeeCmd)
	AdminCmd.AddCommand(setThresholdCmd)
	AdminCmd.AddCommand(getThresholdCmd)
	AdminCmd.AddCommand(unpauseCmd)
	AdminCmd.AddCommand(withdrawCmd)
	AdminCmd.AddCommand(withdrawETHCmd)
	AdminCmd.AddCommand(setDepositNonceCmd)
	AdminCmd.AddCommand(getDestChainIdCmd)
	AdminCmd.AddCommand(setDomainCmd)
	AdminCmd.AddCommand(getDomainCmd)
	AdminCmd.AddCommand(processProposalCmd)
}
