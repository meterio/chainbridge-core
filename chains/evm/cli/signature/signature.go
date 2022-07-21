package signature

import (
	"fmt"

	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/spf13/cobra"
)

var SignatureCmd = &cobra.Command{
	Use:   "signature",
	Short: "Set of commands for interacting with a signature",
	Long:  "Set of commands for interacting with a signature",
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
	SignatureCmd.AddCommand(adminInfoCmd)
	SignatureCmd.AddCommand(relayerInfoCmd)
	//SignatureCmd.AddCommand(queryProposalCmd)
	//SignatureCmd.AddCommand(queryResourceCmd)
	//SignatureCmd.AddCommand(registerGenericResourceCmd)
	//SignatureCmd.AddCommand(registerNativeResourceCmd)
	//SignatureCmd.AddCommand(registerResourceCmd)
	//SignatureCmd.AddCommand(setBurnCmd)
	//SignatureCmd.AddCommand(voteProposalCmd)
}
