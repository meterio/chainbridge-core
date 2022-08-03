package signature

import (
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/contracts/signatures"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmtransaction"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/initialize"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/logger"
	"github.com/ChainSafe/chainbridge-core/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var relayerInfoCmd = &cobra.Command{
	Use:   "relayer-info",
	Short: "Check relayer info",
	Long:  "Check relayer info in an Signature contract",
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
		return RelayerInfoCmd(cmd, args, signatures.NewSignaturesContract(c, SignatureAddr, t))
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := ValidateRelayerInfoFlags(cmd, args)
		if err != nil {
			return err
		}

		ProcessRelayerInfoFlags(cmd, args)
		return nil
	},
}

func BindRelayerInfoFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&Signature, "signature", "", "Signature contract address")
	flags.MarkFlagsAsRequired(cmd, "signature")
}

func init() {
	BindRelayerInfoFlags(relayerInfoCmd)
}

func ValidateRelayerInfoFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Signature) {
		return fmt.Errorf("invalid Signature address %s", Signature)
	}
	return nil
}

func ProcessRelayerInfoFlags(cmd *cobra.Command, args []string) {
	//Erc20Addr = common.HexToAddress(Erc20Address)
	SignatureAddr = common.HexToAddress(Signature)
}

func RelayerInfoCmd(cmd *cobra.Command, args []string, contract *signatures.SignaturesContract) error {
	//contract.AdminSetResource()
	role, err := contract.RelayerRole()
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	count, err := contract.GetRoleMemberCount(role)
	if err != nil {
		log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
		return err
	}

	log.Info().Msgf("[Signature %#x] has %v relayer(s).", SignatureAddr, count)

	var index int64
	for index = 0; index < count.Int64(); index++ {
		addr, err := contract.GetRoleMember(role, index)
		if err != nil {
			log.Error().Err(fmt.Errorf("failed contract call error: %v", err))
			return err
		}
		log.Info().Msgf("%v: %#x", index, addr)
	}

	return nil
}
