package admin

import (
	"errors"
	"fmt"
	"math/big"

	callsUtil "github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/bridge"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/util"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var withdrawETHCmd = &cobra.Command{
	Use:   "withdraw-eth",
	Short: "Withdraw ETH from a handler contract",
	Long:  "The withdraw-eth subcommand withdrawals ETH from a handler contract",
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
		return WithdrawETHCmd(cmd, args, bridge.NewBridgeContract(c, BridgeAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateWithdrawFlags(cmd, args)
		if err != nil {
			return err
		}

		err = ProcessWithdrawFlags(cmd, args)
		if err != nil {
			return err
		}
		return nil
	},
}

func BindWithdrawETHFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Amount, "amount", "", "Token amount to withdraw")
	cmd.Flags().StringVar(&Bridge, "bridge", "", "Bridge contract address")
	cmd.Flags().StringVar(&Handler, "handler", "", "Handler contract address")
	cmd.Flags().StringVar(&Recipient, "recipient", "", "Address to withdraw to")
	cmd.Flags().Uint64Var(&Decimals, "decimals", 18, "ETH token decimals")
	flags.MarkFlagsAsRequired(withdrawETHCmd, "amount", "bridge", "handler", "recipient", "decimals")
}

func init() {
	BindWithdrawETHFlags(withdrawETHCmd)
}

func ValidateWithdrawETHFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Bridge) {
		return fmt.Errorf("invalid bridge address: %s", Bridge)
	}
	if !common.IsHexAddress(Handler) {
		return fmt.Errorf("invalid handler address: %s", Handler)
	}
	if !common.IsHexAddress(Recipient) {
		return fmt.Errorf("invalid recipient address: %s", Recipient)
	}
	if Amount != "" {
		return errors.New("only amount should be set")
	}
	return nil
}

func ProcessWithdrawETHFlags(cmd *cobra.Command, args []string) error {
	var err error

	BridgeAddr = common.HexToAddress(Bridge)
	HandlerAddr = common.HexToAddress(Handler)
	RecipientAddr = common.HexToAddress(Recipient)
	decimals := big.NewInt(int64(Decimals))
	RealAmount, err = callsUtil.UserAmountToWei(Amount, decimals)
	if err != nil {
		return err
	}
	fmt.Println("Real Amount: ", RealAmount)
	return nil
}

func WithdrawETHCmd(cmd *cobra.Command, args []string, contract *bridge.BridgeContract) error {
	h, err := contract.WithdrawETH(
		HandlerAddr, RecipientAddr, RealAmount, transactor.TransactOptions{GasLimit: gasLimit},
	)
	if err != nil {
		log.Error().Err(fmt.Errorf("admin withdrawal ETH error: %v", err))
		return err
	}

	log.Info().Msgf("%s ETH(Wei) were withdrawn from handler contract %s into recipient %s; tx hash: %s", Amount, Handler, Recipient, h.Hex())
	return nil
}
