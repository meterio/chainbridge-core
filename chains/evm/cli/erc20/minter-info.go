package erc20

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls/contracts/erc20"
	"github.com/meterio/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/meterio/chainbridge-core/chains/evm/cli/flags"
	"github.com/meterio/chainbridge-core/chains/evm/cli/initialize"
	"github.com/meterio/chainbridge-core/chains/evm/cli/logger"
	"github.com/meterio/chainbridge-core/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var minterInfoCmd = &cobra.Command{
	Use:   "minter-info",
	Short: "Check minter role info",
	Long:  "Check minter role info in an ERC20 contract",
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
		return MinterInfoCmd(cmd, args, erc20.NewERC20Contract(c, Erc20Addr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateMinterInfoFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessMinterInfoFlags(cmd, args)
		return nil
	},
}

func BindMinterInfoFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Erc20Address, "contract", "", "ERC20 contract address")
	flags.MarkFlagsAsRequired(cmd, "contract")
}

func init() {
	BindMinterInfoFlags(minterInfoCmd)
}

func ValidateMinterInfoFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Erc20Address) {
		return fmt.Errorf("invalid recipient address %s", Recipient)
	}
	return nil
}

func ProcessMinterInfoFlags(cmd *cobra.Command, args []string) {
	Erc20Addr = common.HexToAddress(Erc20Address)
}

func MinterInfoCmd(cmd *cobra.Command, args []string, contract *erc20.ERC20Contract) error {
	role, err := contract.MinterRole()
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	count, err := contract.GetRoleMemberCount(role)
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	log.Info().Msgf("[erc20 %x] has %v minter(s).", Erc20Address, count)

	var index int64
	for index = 0; index < count.Int64(); index++ {
		addr, err := contract.GetRoleMember(role, index)
		if err != nil {
			log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
			return err
		}
		log.Info().Msgf("%v: %x", index, addr)
	}

	return nil
}
