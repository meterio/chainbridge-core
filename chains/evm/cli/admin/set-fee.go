package admin

import (
	"fmt"
	callsUtil "github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var setFeeCmd = &cobra.Command{
	Use:   "set-fee",
	Short: "Set a new fee for deposits",
	Long:  "The set-fee subcommand sets a new fee for deposits",
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
		return SetFeeCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateSetFeeFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessSetFeeFlags(cmd, args)
		return nil
	},
}

func BindSetFeeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Fee, "fee", "", "New fee (in ether)")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().Uint64Var(&Decimals, "decimals", 0, "Base token decimals")
	flags.MarkFlagsAsRequired(cmd, "fee", "bridge")
}

func init() {
	BindSetFeeFlags(setFeeCmd)
}
func ValidateSetFeeFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessSetFeeFlags(cmd *cobra.Command, args []string) {
	BridgeAddr = common.HexToAddress(Bridge)
}

func SetFeeCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Setting new fee
Fee amount: %s
Bridge address: %s`, Fee, Bridge)

	decimals := big.NewInt(int64(Decimals))
	realAmount, err := callsUtil.UserAmountToWei(Fee, decimals)
	if err != nil {
		return err
	}

	_, err = contract.SetFee(realAmount, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
