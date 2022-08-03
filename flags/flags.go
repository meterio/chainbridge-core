package flags

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Flags for running the Chainbridge app
	ConfigFlagName      = "config"
	KeystoreFlagName    = "keystore"
	BlockstoreFlagName  = "blockstore"
	FreshStartFlagName  = "fresh"
	DryFlagName         = "dry"
	LatestBlockFlagName = "latest"
	TestKeyFlagName     = "testkey"
	LogLevelFlagName    = "loglevel"
)

func BindFlags(rootCMD *cobra.Command) {
	rootCMD.PersistentFlags().String(ConfigFlagName, ".", "Path to JSON configuration file")
	_ = viper.BindPFlag(ConfigFlagName, rootCMD.PersistentFlags().Lookup(ConfigFlagName))

	rootCMD.PersistentFlags().String(BlockstoreFlagName, "./lvldbdata", "Specify path for blockstore")
	_ = viper.BindPFlag(BlockstoreFlagName, rootCMD.PersistentFlags().Lookup(BlockstoreFlagName))

	rootCMD.PersistentFlags().Bool(FreshStartFlagName, false, "Disables loading from blockstore at start. Opts will still be used if specified. (default: false)")
	_ = viper.BindPFlag(FreshStartFlagName, rootCMD.PersistentFlags().Lookup(FreshStartFlagName))

	rootCMD.PersistentFlags().Bool(DryFlagName, false, "Dry run mode, do not submit transaction. Opts will still be used if specified. (default: false)")
	_ = viper.BindPFlag(DryFlagName, rootCMD.PersistentFlags().Lookup(DryFlagName))

	rootCMD.PersistentFlags().Bool(LatestBlockFlagName, false, "Overrides blockstore and start block, starts from latest block (default: false)")
	_ = viper.BindPFlag(LatestBlockFlagName, rootCMD.PersistentFlags().Lookup(LatestBlockFlagName))

	rootCMD.PersistentFlags().String(KeystoreFlagName, "./keys", "Path to keystore directory")
	_ = viper.BindPFlag(KeystoreFlagName, rootCMD.PersistentFlags().Lookup(KeystoreFlagName))

	rootCMD.PersistentFlags().String(TestKeyFlagName, "", "Applies a predetermined test keystore to the chains.")
	_ = viper.BindPFlag(TestKeyFlagName, rootCMD.PersistentFlags().Lookup(TestKeyFlagName))

	rootCMD.PersistentFlags().String(LogLevelFlagName, "info", "Set global logging level")
	_ = viper.BindPFlag(LogLevelFlagName, rootCMD.PersistentFlags().Lookup(LogLevelFlagName))
}
