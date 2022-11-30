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

var setSpecialFeeCmd = &cobra.Command{
	Use:   "set-special-fee",
	Short: "Set a new special fee for deposits",
	Long:  "The set-special-fee subcommand sets a new fee for deposits",
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
		return SetSpecialFeeCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateSetSpecialFeeFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessSetSpecialFeeFlags(cmd, args)
		return nil
	},
}

func BindSetSpecialFeeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Fee, "fee", "", "New fee (in ether)")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().Uint64Var(&Decimals, "decimals", 0, "Base token decimals")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of chain")
	flags.MarkFlagsAsRequired(cmd, "fee", "bridge", "domain")
}

func init() {
	BindSetSpecialFeeFlags(setSpecialFeeCmd)
}
func ValidateSetSpecialFeeFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}
	return nil
}

func ProcessSetSpecialFeeFlags(cmd *cobra.Command, args []string) {
	BridgeAddr = common.HexToAddress(Bridge)
}

func SetSpecialFeeCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Setting new fee
Fee amount: %s
Bridge address: %s`, Fee, Bridge)
	decimals := big.NewInt(int64(Decimals))
	realAmount, err := callsUtil.UserAmountToWei(Fee, decimals)
	if err != nil {
		return err
	}

	_, err = contract.SetSpecialFee(DomainID, realAmount, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
