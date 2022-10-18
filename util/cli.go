package util

import (
	"github.com/ChainSafe/chainbridge-core/crypto"
	"github.com/spf13/cobra"
	"math/big"
	"sync"
)

func CallPersistentPreRun(cmd *cobra.Command, args []string) error {
	if parent := cmd.Parent(); parent != nil {
		if parent.PersistentPreRunE != nil {
			return parent.PersistentPreRunE(parent, args)
		}
	}
	return nil
}

var HEAD_STATS = sync.Map{} // make(map[uint8]int64)
var SYNC_STATS = sync.Map{} // make(map[uint8]int64)

var PathKeypair = make(map[string]crypto.Keypair)
var DomainIdToName = make(map[uint8]string)
var DomainIdMappingGasPrice = make(map[uint8]*big.Int)
