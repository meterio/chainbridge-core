package admin

import (
	"fmt"
	callsUtil "github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/transactor"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"math/big"

	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var transferFeeCmd = &cobra.Command{
	Use:   "transfer-fee",
	Short: "Transfer fee to addr",
	Long:  "The transfer-fee subcommand Transfer fee to addr",
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
		return TransferFeeCMD(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateTransferFeeFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessTransferFeeFlags(cmd, args)
		return nil
	},
}

func BindTransferFeeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Fee, "fee", "", "New fee (in ether)")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Account, "account", "", "Account address")
	cmd.Flags().Uint8Var(&DomainID, "domain", 0, "Domain ID of chain")
	flags.MarkFlagsAsRequired(cmd, "fee", "bridge")
}

func init() {
	BindTransferFeeFlags(transferFeeCmd)
}
func ValidateTransferFeeFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address %s", Bridge)
	}

	if !common.IsHexAddress(Account) {
		return fmt.Errorf("invalid Account address %s", Account)
	}
	return nil
}

func ProcessTransferFeeFlags(cmd *cobra.Command, args []string) {
	AccountAddr = common.HexToAddress(Account)
}

func TransferFeeCMD(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	log.Debug().Msgf(`
Transfer fee
Fee amount: %s
to account: %s
Bridge address: %s`, Fee, Account, Bridge)

	decimals := big.NewInt(int64(Decimals))
	realAmount, err := callsUtil.UserAmountToWei(Fee, decimals)
	if err != nil {
		return err
	}

	_, err = contract.TransferFee(AccountAddr, realAmount, transactor.TransactOptions{GasLimit: gasLimit})
	return err
}
